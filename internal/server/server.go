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

// Run loads server.yaml from configPath and runs the sigils daemon until ctx
// is cancelled or the HTTPS or IPC server fails. Shutdown stops the HTTPS and
// IPC servers, waits for the renewal scheduler, and closes the store last.
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
	r := scheduler.New(acme.NewIssuer(db.Accounts), db, changes.Notify, nil)
	runtimeConfig := newServerConfigRuntime(configPath, cfg, changes.Notify, r)
	schedulerDone := make(chan struct{})
	go func() {
		defer close(schedulerDone)
		_ = r.RunDynamic(ctx, runtimeConfig.Current)
	}()

	// Enrollment tokens are created over IPC and redeemed over HTTPS.
	enrollSrv := enroll.NewServer(db.Tokens, db.Clients, miniCA)

	// The errors of net/http servers, such as the failed TLS handshakes of
	// every scanner on the internet, go to the service log but are not
	// events.
	errorLog := slog.NewLogLogger(logs.Sink, slog.LevelInfo)

	// IPC server. Requests inherit ctx, so once shutdown starts a manual
	// renewal still waiting for its certificate's lock or an issuance slot
	// gives up. One already running continues, as lego ignores ctx, and stores
	// its certificate if it finishes before the store closes: shutdown waits
	// for the scheduler's issuances but not for manual renewals.
	ipcSrv := ipc.NewServer(ipc.ServerDeps{
		DB:     db,
		Server: &ipc.ServerControlDeps{Reload: runtimeConfig.Reload},
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
				return createToken(ctx, enrollSrv, db.Clients, runtimeConfig.Current(), req)
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
		ServerCfg:     cfg,
		CurrentServer: runtimeConfig.Current,
		DB:            db,
		MiniCA:        miniCA,
		DataDir:       cfg.Server.DataDir,
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
	// until shutdownTimeout.
	cancel()
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancelShutdown()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		_ = httpSrv.Close()
	}
	if err := ipcSrv.Shutdown(shutdownCtx); err != nil {
		_ = ipcSrv.Close()
	}
	<-schedulerDone
	return runErr
}

// createToken issues an enrollment token bound to the public base URL of the
// running configuration, the URL clients use to reach this server. It refuses
// the name of an enrolled client unless req.Replace is set: enrollment
// replaces the client of the name, so a mistyped name would hand another
// host's certificates and keys to the new one without a word.
func createToken(ctx context.Context, enrollSrv *enroll.Server, clients *store.ClientRepo, cfg *config.ServerConfig, req ipc.CreateTokenRequest) (ipc.CreateTokenResponse, error) {
	name, ttl := req.Name, req.TTL
	if ttl <= 0 {
		return ipc.CreateTokenResponse{}, fmt.Errorf("token lifetime must be positive, got %s", ttl)
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
	if !req.Replace {
		_, err := clients.Get(ctx, name, nil)
		if err == nil {
			return ipc.CreateTokenResponse{}, fmt.Errorf("client %q is already enrolled: the host that enrolls with a token for this name replaces it, "+
				"takes over its certificates and locks the enrolled host out; create the token with --replace if that is intended", name)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return ipc.CreateTokenResponse{}, fmt.Errorf("look up client %q: %w", name, err)
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
		ServerURL:           serverURL,
		PublicURLConfigured: cfg.Server.PublicURL != "",
	}, nil
}
