package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"time"

	legolog "github.com/go-acme/lego/v4/log"

	"github.com/Oganneson-Studio/sigil/internal/acme"
	"github.com/Oganneson-Studio/sigil/internal/api"
	"github.com/Oganneson-Studio/sigil/internal/ca"
	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/enroll"
	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/logging"
	"github.com/Oganneson-Studio/sigil/internal/scheduler"
	"github.com/Oganneson-Studio/sigil/internal/store"
	"github.com/Oganneson-Studio/sigil/internal/version"
)

// shutdownTimeout bounds how long in-flight HTTPS and IPC requests may delay
// daemon shutdown.
const shutdownTimeout = 10 * time.Second

// maxTokenLifetime bounds the lifetime of an enrollment token: anyone who
// reads one before it is used can enroll with it.
const maxTokenLifetime = 7 * 24 * time.Hour

// issuanceStopTimeout bounds the whole shutdown, which waits for the
// issuances of the scheduler. lego cannot be interrupted, and an issuance
// waiting for a DNS provider can take tens of minutes, or hang on a provider
// whose API client has no overall timeout. Past the bound, shutdown abandons
// the issuances, with the certificates they would store and the DNS records
// they would clean up, and kills the programs of exec DNS providers they
// still run. Tests shorten it.
var issuanceStopTimeout = 30 * time.Second

// Run loads server.yaml from configPath and runs the sigils daemon until ctx
// is cancelled or the HTTPS or IPC server fails. Shutdown stops the HTTPS and
// IPC servers, waits for the renewal scheduler for issuanceStopTimeout at
// most, and closes the store last.
//
// logs is the logging that logging.Setup made the default: the IPC API serves
// its events, and the errors of the HTTPS and IPC servers go to its sink
// alone.
func Run(ctx context.Context, configPath string, logs logging.Logs) error {
	cfg, err := config.LoadServer(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	db, err := store.Open(filepath.Join(cfg.Server.DataDir, "sigils.db"))
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	// Deferred first so it runs last: after both servers are shut down and the
	// scheduler has returned. A request still running when a server's shutdown
	// times out is abandoned by Close and may see the store close under it.
	defer db.Close()

	miniCA, err := ca.Bootstrap(cfg.Server.DataDir)
	if err != nil {
		return fmt.Errorf("init CA: %w", err)
	}

	// The HTTPS certificate: the configured TLS files, or one the mini-CA
	// issues. Either is replaced without a restart.
	serverTLS, err := newTLSSource(miniCA, cfg, time.Now)
	if err != nil {
		return fmt.Errorf("server TLS cert: %w", err)
	}

	// Bind both listeners before starting background work, so a busy address
	// or a daemon that is already running fails fast instead of waiting for
	// the scheduler's first issuance.
	httpsListener, err := net.Listen("tcp", cfg.Server.Listen)
	if err != nil {
		return fmt.Errorf("https listen: %w", err)
	}
	ipcListener, err := ipc.Listen(cfg.Server.IPCSocket)
	if err != nil {
		_ = httpsListener.Close()
		return fmt.Errorf("ipc listen: %w", err)
	}
	// Before any other event, and before either server takes a request.
	slog.Info("sigils started", "version", version.Version, "listen", cfg.Server.Listen, "public_url", cfg.Server.PublicURL)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Renewal scheduler. lego keeps DNS resolvers in a process-wide variable,
	// so they are set once, before any issuance can run; changing them needs a
	// restart. So is its logger, which writes to stderr by default.
	acme.SetDNSResolvers(cfg.ACME.DNSResolvers)
	legolog.Logger = log.New(legoLog{}, "", 0)
	// Stored certificates and published reloads wake the clients waiting in
	// GET /v1/sync.
	changes := api.NewChanges()
	// The programs of exec DNS providers are killed when Run returns, not
	// when ctx ends: the issuances that shutdown waits for below may still
	// need them, to clean up their records.
	programs, killPrograms := context.WithCancel(context.WithoutCancel(ctx))
	defer killPrograms()
	r := scheduler.New(acme.NewIssuer(programs, db.Accounts), db, changes.Notify, nil)
	runtimeConfig := newServerConfigRuntime(configPath, cfg, changes.Notify, r)
	schedulerDone := make(chan struct{})
	go func() {
		defer close(schedulerDone)
		_ = r.RunDynamic(ctx, runtimeConfig.Current)
	}()

	// Enrollment tokens are created over IPC and redeemed over HTTPS.
	enrollSrv := enroll.NewServer(db, miniCA)

	// The errors of net/http servers, such as the failed TLS handshakes of
	// every scanner on the internet, go to the service log but are not
	// events.
	errorLog := slog.NewLogLogger(logs.Sink, slog.LevelInfo)

	// IPC server. Requests inherit ctx, so once shutdown starts a manual
	// renewal still waiting for its certificate's lock or an issuance slot
	// gives up. One already running continues, as lego ignores ctx, and stores
	// its certificate if it finishes before the store closes: shutdown waits
	// for the scheduler's issuances, up to issuanceStopTimeout, but not for
	// manual renewals.
	ipcSrv := ipc.NewServer(ipc.ServerDeps{
		DB: db,
		Server: &ipc.ServerControlDeps{
			Reload:            runtimeConfig.Reload,
			ConfigPath:        configPath,
			AddCertificate:    runtimeConfig.AddCertificate,
			RemoveCertificate: runtimeConfig.RemoveCertificate,
		},
		Certificates: &ipc.CertificateControlDeps{
			Renew: func(ctx context.Context, name string) error {
				slog.Info("manual renewal requested", "cert", name)
				return r.RenewNamed(ctx, runtimeConfig.Current, name)
			},
			Current:     runtimeConfig.Current,
			Issuing:     r.Issuing,
			RenewalPlan: r.RenewalPlan,
		},
		Tokens: &ipc.TokenControlDeps{
			Create: func(ctx context.Context, req ipc.CreateTokenRequest) (ipc.CreateTokenResponse, error) {
				return createToken(ctx, enrollSrv, db, runtimeConfig.Current(), req)
			},
		},
		Events: logs.Events,
	})
	ipcSrv.BaseContext = func(net.Listener) context.Context { return ctx }
	ipcSrv.ErrorLog = errorLog
	ipcDone := make(chan error, 1)
	go func() { ipcDone <- ipcSrv.Serve(ipcListener) }()

	// HTTPS server.
	httpSrv := api.New(api.Deps{
		CurrentServer: runtimeConfig.Current,
		DB:            db,
		MiniCA:        miniCA,
		EnrollServer:  enrollSrv,
		Changes:       changes,
		Done:          ctx.Done(),
	}, serverTLS.GetCertificate)
	// Anyone who reaches the port can make it log, so it logs a few lines a
	// minute at most.
	httpSrv.ErrorLog = log.New(&limitedWriter{w: errorLog.Writer(), clock: time.Now}, "", 0)
	httpsDone := make(chan error, 1)
	go func() { httpsDone <- httpSrv.ServeTLS(httpsListener, "", "") }()

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-httpsDone:
		runErr = fmt.Errorf("serve https: %w", err)
	case err := <-ipcDone:
		runErr = fmt.Errorf("serve ipc: %w", err)
	}
	slog.Info("sigils stopping")

	// Stop taking requests, then wait for background work, then close the
	// store (deferred above). Cancelling before Shutdown answers the requests
	// waiting in GET /v1/sync at once, which would otherwise hold Shutdown
	// until shutdownTimeout. The scheduler stops with ctx as well, so the
	// bound on its issuances counts from here.
	cancel()
	abandon := time.NewTimer(issuanceStopTimeout)
	defer abandon.Stop()
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancelShutdown()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		_ = httpSrv.Close()
	}
	if err := ipcSrv.Shutdown(shutdownCtx); err != nil {
		_ = ipcSrv.Close()
	}
	select {
	case <-schedulerDone:
	case <-abandon.C:
		// The operator may have DNS records to clean up for these.
		var issuing []string
		for _, spec := range runtimeConfig.Current().Certificates {
			if r.Issuing(spec.Name) {
				issuing = append(issuing, spec.Name)
			}
		}
		slog.Warn("certificate issuance abandoned at shutdown", "certs", strings.Join(issuing, ","))
	}
	return runErr
}

// createToken issues an enrollment token bound to the public base URL of the
// running configuration, the URL clients use to reach this server.
//
// Enrollment replaces the client of the token's name, so a name typed twice,
// or the name of another host, would hand one host's certificates and keys
// to another without a word. Unless req.Replace is set, createToken refuses
// the name of an enrolled client, and a name with an unused token that has
// not expired, whose host would replace the one that enrolls first. With
// req.Replace, it revokes the unused tokens of the name, which would replace
// the host that enrolls with the new one.
func createToken(ctx context.Context, enrollSrv *enroll.Server, db *store.DB, cfg *config.ServerConfig, req ipc.CreateTokenRequest) (ipc.CreateTokenResponse, error) {
	name, ttl := req.Name, req.TTL
	if ttl <= 0 {
		return ipc.CreateTokenResponse{}, fmt.Errorf("token lifetime must be positive, got %s", ttl)
	}
	if ttl > maxTokenLifetime {
		return ipc.CreateTokenResponse{}, fmt.Errorf("token lifetime must be at most %s, got %s", maxTokenLifetime, ttl)
	}
	serverURL := cfg.PublicBaseURL()
	if cfg.Server.PublicURL == "" {
		// Without public_url the base URL is derived from server.listen, which
		// the daemon listens on, so it splits into a host and a port.
		host, _, _ := net.SplitHostPort(cfg.Server.Listen)
		if host == "" || net.ParseIP(host).IsUnspecified() {
			return ipc.CreateTokenResponse{}, fmt.Errorf("server.public_url must be set: server.listen %q names no host clients can reach", cfg.Server.Listen)
		}
		// The token carries the URL to sigilc, which refuses one that could
		// not be server.public_url: check it before the token is stored.
		if err := config.ValidatePublicURL(serverURL); err != nil {
			return ipc.CreateTokenResponse{}, fmt.Errorf("server.public_url must be set: the URL derived from server.listen %w", err)
		}
	}
	tokens, err := db.Tokens.List(ctx, nil)
	if err != nil {
		return ipc.CreateTokenResponse{}, fmt.Errorf("list enrollment tokens: %w", err)
	}
	var unused []*store.TokenRecord
	for _, tok := range tokens {
		if tok.Name == name && tok.UsedAt.IsZero() {
			unused = append(unused, tok)
		}
	}
	if !req.Replace {
		_, err := db.Clients.Get(ctx, name, nil)
		if err == nil {
			return ipc.CreateTokenResponse{}, fmt.Errorf("client %q is already enrolled: the host that enrolls with a token for this name replaces it, "+
				"takes over its certificates and locks the enrolled host out; %w", name, ipc.ErrReplaceRequired)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return ipc.CreateTokenResponse{}, fmt.Errorf("look up client %q: %w", name, err)
		}
		now := time.Now()
		for _, tok := range unused {
			if now.Before(tok.ExpiresAt) {
				return ipc.CreateTokenResponse{}, fmt.Errorf("enrollment token %s for %q is unused: of the hosts that enroll with tokens for one name, "+
					"each replaces the one before, takes over its certificates and locks it out; %w", tok.TokenID, name, ipc.ErrReplaceRequired)
			}
		}
	}
	revoked := 0
	if req.Replace {
		// A replacement revokes the unused tokens of the name: whichever
		// host enrolled with one of them last would replace the host of the
		// new one.
		for _, tok := range unused {
			if err := db.Tokens.Delete(ctx, tok.TokenID, nil); err != nil {
				return ipc.CreateTokenResponse{}, fmt.Errorf("revoke enrollment token %s: %w", tok.TokenID, err)
			}
			slog.Info("enrollment token revoked", "token", tok.TokenID)
			revoked++
		}
	}
	token, err := enrollSrv.Create(ctx, serverURL, name, ttl)
	if err != nil {
		return ipc.CreateTokenResponse{}, err
	}
	// An event names the token by its ID: the token itself enrolls a client.
	payload, err := enroll.DecodeToken(token)
	if err != nil {
		return ipc.CreateTokenResponse{}, err
	}
	slog.Info("enrollment token created", "token", payload.TokenID, "client", payload.Name, "expires_at", payload.ExpiresAt)
	return ipc.CreateTokenResponse{
		Token:               token,
		TokenID:             payload.TokenID,
		ExpiresAt:           payload.ExpiresAt,
		Revoked:             revoked,
		ServerURL:           serverURL,
		PublicURLConfigured: cfg.Server.PublicURL != "",
	}, nil
}
