package commands

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Oganneson-Studio/sigil/internal/config"
)

type configPublisher interface {
	PublishConfig(context.Context, func()) error
}

// serverConfigRuntime owns the configuration visible to the running daemon.
// Reload validates every change before updating any consumer.
type serverConfigRuntime struct {
	path string

	mu      sync.Mutex
	current atomic.Pointer[config.ServerConfig]
	renewer configPublisher
}

func newServerConfigRuntime(path string, initial *config.ServerConfig, publishers ...configPublisher) *serverConfigRuntime {
	runtime := &serverConfigRuntime{
		path: path,
	}
	if len(publishers) > 0 {
		runtime.renewer = publishers[0]
	}
	runtime.current.Store(initial)
	return runtime
}

func (r *serverConfigRuntime) Current() *config.ServerConfig {
	return r.current.Load()
}

func (r *serverConfigRuntime) Reload(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return err
	}
	next, err := config.LoadServer(r.path)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	previous := r.current.Load()
	if err := validateHotReload(previous, next); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// Every runtime consumer loads this same immutable snapshot, so one store
	// publishes the new generation without a mixed old/new configuration window.
	publish := func() { r.current.Store(next) }
	if r.renewer != nil {
		return r.renewer.PublishConfig(ctx, publish)
	}
	publish()
	return nil
}

func validateHotReload(previous, next *config.ServerConfig) error {
	if previous == nil || next == nil {
		return fmt.Errorf("server configuration is unavailable")
	}

	var immutable []string
	if previous.Server.Listen != next.Server.Listen {
		immutable = append(immutable, "server.listen")
	}
	if previous.Server.DataDir != next.Server.DataDir {
		immutable = append(immutable, "server.data_dir")
	}
	if previous.Server.IPCSocket != next.Server.IPCSocket {
		immutable = append(immutable, "server.ipc_socket")
	}
	if previous.Server.PublicURL != next.Server.PublicURL {
		immutable = append(immutable, "server.public_url")
	}
	if previous.Server.TLSCertFile != next.Server.TLSCertFile {
		immutable = append(immutable, "server.tls_cert_file")
	}
	if previous.Server.TLSKeyFile != next.Server.TLSKeyFile {
		immutable = append(immutable, "server.tls_key_file")
	}
	if len(immutable) > 0 {
		return fmt.Errorf(
			"cannot hot reload changes to %s; restart sigils to apply them",
			strings.Join(immutable, ", "),
		)
	}
	return nil
}
