package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/acme"
	"github.com/Oganneson-Studio/sigil/internal/api"
	"github.com/Oganneson-Studio/sigil/internal/ca"
	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/enroll"
	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/scheduler"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

// shutdownTimeout bounds how long in-flight HTTPS and IPC requests may delay
// daemon shutdown.
const shutdownTimeout = 10 * time.Second

// Run loads server.yaml from configPath and runs the sigils daemon until ctx
// is cancelled or the HTTPS or IPC server fails. Shutdown stops the HTTPS and
// IPC servers, waits for the renewal scheduler, and closes the store last.
func Run(ctx context.Context, configPath string) error {
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

	// Issue (or re-use) a TLS server certificate signed by the mini-CA.
	serverTLSCert, err := serverTLSCertificate(miniCA, cfg)
	if err != nil {
		return fmt.Errorf("server TLS cert: %w", err)
	}

	// Bind both listeners before starting background work, so a busy address
	// fails fast instead of waiting for the scheduler's first issuance. HTTPS
	// goes first: on Unix ipc.Listen removes an existing socket, and a second
	// instance that cannot get the HTTPS address must not take the running
	// daemon's management endpoint with it.
	httpsListener, err := net.Listen("tcp", cfg.Server.Listen)
	if err != nil {
		return fmt.Errorf("https listen: %w", err)
	}
	ipcListener, err := ipc.Listen(cfg.Server.IPCSocket)
	if err != nil {
		_ = httpsListener.Close()
		return fmt.Errorf("ipc listen: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Renewal scheduler.
	pushNotifier := scheduler.NewHTTPPushNotifier(nil)
	r := scheduler.New(acme.NewIssuer(db.Accounts), db.Certs, pushNotifier, nil)
	runtimeConfig := newServerConfigRuntime(configPath, cfg, r)
	schedulerDone := make(chan struct{})
	go func() {
		defer close(schedulerDone)
		_ = r.RunDynamic(ctx, runtimeConfig.Current)
	}()

	// IPC server. Requests inherit ctx, so once shutdown starts a manual
	// renewal can no longer be stored: lego ignores ctx and finishes the ACME
	// order, then the upsert fails and the new certificate is discarded.
	ipcSrv := ipc.NewServer(ipc.ServerDeps{
		DB:     db,
		Server: &ipc.ServerControlDeps{Reload: runtimeConfig.Reload},
		Certificates: &ipc.CertificateControlDeps{
			Renew: func(ctx context.Context, name string) error {
				return r.RenewNamed(ctx, runtimeConfig.Current, name)
			},
		},
	})
	ipcSrv.BaseContext = func(net.Listener) context.Context { return ctx }
	ipcDone := make(chan error, 1)
	go func() { ipcDone <- ipcSrv.Serve(ipcListener) }()

	// HTTPS server with mini-CA-signed server cert.
	httpSrv := api.New(api.Deps{
		ServerCfg:     cfg,
		CurrentServer: runtimeConfig.Current,
		DB:            db,
		MiniCA:        miniCA,
		DataDir:       cfg.Server.DataDir,
		EnrollServer:  enroll.NewServer(db.Tokens, db.Clients, miniCA),
	}, serverTLSCert)
	httpsDone := make(chan error, 1)
	go func() { httpsDone <- httpSrv.ServeTLS(httpsListener, "", "") }()
	fmt.Printf("sigils listening on %s (TLS)\n", cfg.Server.Listen)

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-httpsDone:
		runErr = fmt.Errorf("serve https: %w", err)
	case err := <-ipcDone:
		runErr = fmt.Errorf("serve ipc: %w", err)
	}

	// Stop taking requests, then wait for background work, then close the
	// store (deferred above).
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

// serverTLSCertificate builds the hosts list from the config and issues a
// server TLS cert signed by the mini-CA.
func serverTLSCertificate(miniCA *ca.MiniCA, cfg *config.ServerConfig) (tls.Certificate, error) {
	if cfg.Server.TLSCertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("load configured TLS certificate: %w", err)
		}
		return cert, nil
	}

	hosts := []string{"localhost", "127.0.0.1", "::1"}

	// Extract hostname from public_url if set.
	if cfg.Server.PublicURL != "" {
		if u, err := url.Parse(cfg.Server.PublicURL); err == nil && u.Hostname() != "" {
			hosts = append(hosts, u.Hostname())
		}
	}

	// Extract hostname from listen address if it has one (e.g. "sigil.internal:8443").
	if h, _, err := net.SplitHostPort(cfg.Server.Listen); err == nil && h != "" {
		hosts = append(hosts, h)
	}

	certPEM, keyPEM, err := miniCA.IssueServerCert(hosts)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}
