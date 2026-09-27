package agent

import (
	"context"
	"fmt"

	"github.com/Oganneson-Studio/sigil/internal/client"
	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/enroll"
	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/version"
)

// Run loads client.yaml from configPath and runs the sigilc daemon until ctx
// is cancelled. Cancellation is a clean stop and returns nil.
func Run(ctx context.Context, configPath string) error {
	cfg, err := config.LoadClient(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
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
	control := &ipc.ClientControlDeps{
		State: func(context.Context) (ipc.ClientState, error) {
			status := c.Status()
			return ipc.ClientState{
				Name:       status.Name,
				ServerURL:  status.ServerURL,
				Online:     status.Online,
				LastPullAt: status.LastPullAt,
				LastError:  status.LastError,
				Certs:      status.Certs,
			}, nil
		},
		Fetch: c.Fetch,
		Reload: func(context.Context) error {
			updated, err := config.LoadClient(configPath)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			return c.Reload(updated)
		},
	}
	// The IPC server stops with ctx, so it also stops when Run returns an error.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = ipc.Serve(ctx, ipcListener, ipc.ServerDeps{Client: control}) }()

	fmt.Printf("sigilc %s starting (server: %s)\n", version.Version, cfg.Client.ServerURL)
	err = c.Run(ctx)
	if ctx.Err() != nil {
		return nil
	}
	return err
}
