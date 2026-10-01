package server

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Oganneson-Studio/certfold/internal/config"
)

type configPublisher interface {
	PublishConfig(context.Context, func()) error
}

// serverConfigRuntime owns the configuration visible to the running daemon,
// and server.yaml, which it reads on Reload and changes on AddCertificate and
// RemoveCertificate. Each validates every change before updating any
// consumer.
type serverConfigRuntime struct {
	path string
	// changed is called after every published configuration. The daemon
	// passes a function that wakes the clients waiting in GET /v1/sync.
	changed func()

	mu      sync.Mutex
	current atomic.Pointer[config.ServerConfig]
	renewer configPublisher
}

func newServerConfigRuntime(path string, initial *config.ServerConfig, changed func(), renewer configPublisher) *serverConfigRuntime {
	runtime := &serverConfigRuntime{
		path:    path,
		changed: changed,
		renewer: renewer,
	}
	runtime.current.Store(initial)
	return runtime
}

func (r *serverConfigRuntime) Current() *config.ServerConfig {
	return r.current.Load()
}

func (r *serverConfigRuntime) Reload(ctx context.Context) (err error) {
	// Deferred first, so it logs once the lock is released.
	defer func() {
		if err != nil {
			slog.Warn("configuration reload rejected", "error", err)
		} else {
			slog.Info("configuration reloaded")
		}
	}()
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
	return r.publish(ctx, next)
}

// AddCertificate appends spec to the certificates of server.yaml and applies
// the result. The CA of spec defaults to acme.default_ca.
func (r *serverConfigRuntime) AddCertificate(ctx context.Context, spec config.CertificateSpec) error {
	err := r.edit(ctx, func(raw []byte) ([]byte, *config.ServerConfig, error) {
		return config.AddCertificateSpec(raw, spec)
	})
	if err == nil {
		slog.Info("certificate added to the configuration", "cert", spec.Name)
	}
	return err
}

// RemoveCertificate removes the named certificate from server.yaml and
// applies the result. Its stored material stays in the database.
func (r *serverConfigRuntime) RemoveCertificate(ctx context.Context, name string) error {
	err := r.edit(ctx, func(raw []byte) ([]byte, *config.ServerConfig, error) {
		return config.RemoveCertificateSpec(raw, name)
	})
	if err == nil {
		slog.Info("certificate removed from the configuration", "cert", name)
	}
	return err
}

// edit changes server.yaml with change, which returns the new file and the
// configuration it parses into, and applies the result. The daemon parses it
// with its own environment, which holds what the ${VAR} references of the
// file need.
//
// The change is written only if Reload would apply the new file: a file that
// already differs from the running configuration in a way that needs a
// restart is left as it is. Once the new file is written, the caller going
// away does not stop it from being applied, and should applying it fail,
// the file is put back as it was.
func (r *serverConfigRuntime) edit(ctx context.Context, change func([]byte) ([]byte, *config.ServerConfig, error)) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	raw, err := os.ReadFile(r.path)
	if err != nil {
		return fmt.Errorf("read %s: %w", r.path, err)
	}
	updated, next, err := change(raw)
	if err != nil {
		return err
	}
	if err := validateHotReload(r.current.Load(), next); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := writeConfigFile(r.path, updated); err != nil {
		return err
	}
	if err := r.publish(context.WithoutCancel(ctx), next); err != nil {
		if restoreErr := writeConfigFile(r.path, raw); restoreErr != nil {
			return fmt.Errorf("%w; the change stays in %s without being applied, as restoring the file failed: %v", err, r.path, restoreErr)
		}
		return err
	}
	return nil
}

// publish makes next the running configuration. The caller holds mu.
func (r *serverConfigRuntime) publish(ctx context.Context, next *config.ServerConfig) error {
	// Every runtime consumer loads this same immutable snapshot, so one store
	// publishes the new generation without a mixed old/new configuration window.
	if err := r.renewer.PublishConfig(ctx, func() { r.current.Store(next) }); err != nil {
		return err
	}
	// After PublishConfig rather than in its callback, which may only perform
	// the atomic publication.
	r.changed()
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
	// lego keeps the DNS resolvers in a process-wide variable that certfolds sets
	// once at startup; changing it under running issuances would be a race.
	if !slices.Equal(previous.ACME.DNSResolvers, next.ACME.DNSResolvers) {
		immutable = append(immutable, "acme.dns_resolvers")
	}
	if len(immutable) > 0 {
		return fmt.Errorf(
			"cannot hot reload changes to %s; restart certfolds to apply them",
			strings.Join(immutable, ", "),
		)
	}
	return nil
}
