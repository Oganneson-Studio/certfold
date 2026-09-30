package agent

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/Oganneson-Studio/sigil/internal/client"
	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/enroll"
	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/logging"
	"github.com/Oganneson-Studio/sigil/internal/securefile"
	"github.com/Oganneson-Studio/sigil/internal/version"
)

// Run loads client.yaml from configPath and runs the sigilc daemon until ctx
// is cancelled. Cancellation is a clean stop and returns nil.
//
// logs is the logging that logging.Setup made the default: the IPC API serves
// its events, and the errors of the IPC server go to its sink alone.
func Run(ctx context.Context, configPath string, logs logging.Logs) error {
	// client.yaml names the on_change programs sigilc runs, and data_dir
	// holds the certificates and keys it writes to the outputs.
	if err := securefile.CheckDirectory(filepath.Dir(configPath)); err != nil {
		return fmt.Errorf("configuration directory: %w", err)
	}
	cfg, err := config.LoadClient(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if err := securefile.CheckDirectory(cfg.Client.DataDir); err != nil {
		return fmt.Errorf("data directory: %w", err)
	}

	c, err := client.New(cfg, client.WithIdentitySaver(func(caCert, clientCert, clientKey string) error {
		return enroll.SaveIdentity(configPath, caCert, clientCert, clientKey)
	}))
	if err != nil {
		return fmt.Errorf("init client: %w", err)
	}

	// IPC server.
	ipcSocket := cfg.Client.IPCSocket
	if ipcSocket == "" {
		ipcSocket = ipc.DefaultClientSocket()
	}
	ipcListener, err := ipc.Listen(ipcSocket)
	if err != nil {
		return fmt.Errorf("ipc listen: %w", err)
	}
	// Before the IPC server takes a request. Loading the store may have
	// logged already.
	slog.Info("sigilc started", "version", version.Version, "server", cfg.Client.ServerURL)
	control := &ipc.ClientControlDeps{
		State: func(context.Context) (ipc.ClientState, error) {
			status := c.Status()
			certs := make([]ipc.ClientCertState, 0, len(status.Certs))
			for _, cert := range status.Certs {
				certs = append(certs, ipc.ClientCertState(cert))
			}
			return ipc.ClientState{
				Name:       status.Name,
				ServerURL:  status.ServerURL,
				Online:     status.Online,
				LastPullAt: status.LastPullAt,
				LastError:  status.LastError,
				Certs:      certs,
			}, nil
		},
		Fetch: c.Fetch,
		Reload: func(context.Context) error {
			return c.Reload(func() (*config.ClientConfig, error) { return config.LoadClient(configPath) })
		},
	}
	ipcSrv := ipc.NewServer(ipc.ServerDeps{Client: control, Events: logs.Events})
	// Its errors go to the service log but are not events.
	ipcSrv.ErrorLog = slog.NewLogLogger(logs.Sink, slog.LevelInfo)
	// The IPC server stops with ctx, so it also stops when Run returns an error.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	context.AfterFunc(ctx, func() { _ = ipcSrv.Close() })
	go func() { _ = ipcSrv.Serve(ipcListener) }()

	err = c.Run(ctx)
	slog.Info("sigilc stopping")
	if ctx.Err() != nil {
		return nil
	}
	return err
}
