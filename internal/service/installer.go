package service

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	ksvc "github.com/kardianos/service"
)

// Daemon is the application logic that the system service runs.
// Start must return promptly; the actual work runs in a goroutine.
// Stop must return within a few seconds.
type Daemon interface {
	Start(s ksvc.Service) error
	Stop(s ksvc.Service) error
}

// Role distinguishes the server binary from the client binary.
type Role int

const (
	RoleServer Role = iota
	RoleClient
)

// Config carries the parameters for creating a system service.
type Config struct {
	Role       Role
	ConfigPath string // path to server.yaml / client.yaml passed as --config
}

// New creates a kardianos Service for the given daemon and config.
// The returned Service can be Run() to start the daemon loop, or used for
// install / uninstall / start / stop / restart / status operations.
func New(d Daemon, cfg Config) (ksvc.Service, error) {
	sc := buildServiceConfig(cfg)
	return ksvc.New(d, sc)
}

func buildServiceConfig(cfg Config) *ksvc.Config {
	name, displayName, desc, cfgDefault := roleAttrs(cfg.Role)

	configPath := cfg.ConfigPath
	if configPath == "" {
		configPath = cfgDefault
	}

	args := []string{"serve", "--config", configPath}

	sc := &ksvc.Config{
		Name:        name,
		DisplayName: displayName,
		Description: desc,
		Arguments:   args,
	}

	// Platform-specific tuning.
	switch runtime.GOOS {
	case "linux":
		sc.Dependencies = []string{
			"After=network-online.target",
			"Wants=network-online.target",
		}
		sc.Option = ksvc.KeyValue{
			"Restart":       "on-failure",
			"RestartSec":    "5",
			"StandardOutput": "journal",
			"StandardError":  "journal",
		}
	case "darwin":
		sc.Option = ksvc.KeyValue{
			"KeepAlive": true,
		}
	}

	return sc
}

func roleAttrs(r Role) (name, displayName, desc, defaultConfig string) {
	switch r {
	case RoleServer:
		return "sigils", "Sigil Server",
			"Sigil certificate management server (ACME issuer + distributor)",
			defaultServerConfigPath()
	default: // RoleClient
		return "sigilc", "Sigil Client",
			"Sigil certificate client (pulls and writes certificates to disk)",
			defaultClientConfigPath()
	}
}

// Install registers the service with the OS service manager.
func Install(d Daemon, cfg Config) error {
	svc, err := New(d, cfg)
	if err != nil {
		return err
	}
	if err := svc.Install(); err != nil {
		return fmt.Errorf("install service: %w", err)
	}
	return nil
}

// Uninstall removes the service from the OS service manager.
func Uninstall(d Daemon, cfg Config) error {
	svc, err := New(d, cfg)
	if err != nil {
		return err
	}
	if err := svc.Uninstall(); err != nil {
		return fmt.Errorf("uninstall service: %w", err)
	}
	return nil
}

// Start signals the OS service manager to start the service.
func Start(d Daemon, cfg Config) error {
	svc, err := New(d, cfg)
	if err != nil {
		return err
	}
	if err := svc.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	return nil
}

// Stop signals the OS service manager to stop the service.
func Stop(d Daemon, cfg Config) error {
	svc, err := New(d, cfg)
	if err != nil {
		return err
	}
	if err := svc.Stop(); err != nil {
		return fmt.Errorf("stop service: %w", err)
	}
	return nil
}

// Restart signals the OS service manager to restart the service.
func Restart(d Daemon, cfg Config) error {
	svc, err := New(d, cfg)
	if err != nil {
		return err
	}
	if err := svc.Restart(); err != nil {
		return fmt.Errorf("restart service: %w", err)
	}
	return nil
}

// StatusText returns a human-readable service status string.
func StatusText(d Daemon, cfg Config) (string, error) {
	svc, err := New(d, cfg)
	if err != nil {
		return "", err
	}
	st, err := svc.Status()
	if err != nil {
		return "", fmt.Errorf("query status: %w", err)
	}
	switch st {
	case ksvc.StatusRunning:
		return "Running", nil
	case ksvc.StatusStopped:
		return "Stopped", nil
	default:
		return "NotInstalled", nil
	}
}

// DefaultServerConfigPath returns the platform default path for server.yaml.
func DefaultServerConfigPath() string { return defaultServerConfigPath() }

// DefaultClientConfigPath returns the platform default path for client.yaml.
func DefaultClientConfigPath() string { return defaultClientConfigPath() }

// noopDaemon is used when we only need the kardianos service handle for
// control operations (install/uninstall/start/stop/restart/status) without
// actually running any logic.
type noopDaemon struct{}

func (n *noopDaemon) Start(_ ksvc.Service) error { return nil }
func (n *noopDaemon) Stop(_ ksvc.Service) error  { return nil }

// NoopDaemon returns a Daemon that does nothing, suitable for control-only
// operations where no real serve logic is needed.
func NoopDaemon() Daemon { return &noopDaemon{} }

// contextDaemon wraps a function that runs until ctx is cancelled.
type contextDaemon struct {
	run func(ctx context.Context) error
	ctx context.Context
	cancel context.CancelFunc
	done   chan error
}

func (d *contextDaemon) Start(_ ksvc.Service) error {
	d.done = make(chan error, 1)
	go func() {
		d.done <- d.run(d.ctx)
	}()
	return nil
}

func (d *contextDaemon) Stop(_ ksvc.Service) error {
	d.cancel()
	<-d.done
	return nil
}

// NewContextDaemon wraps a function as a Daemon. The function should block
// until ctx is cancelled, then return promptly.
func NewContextDaemon(run func(ctx context.Context) error) Daemon {
	ctx, cancel := context.WithCancel(context.Background())
	return &contextDaemon{run: run, ctx: ctx, cancel: cancel}
}

// UnpackClients copies sigilc binaries from fsys into dataDir/binaries/.
// Returns (n, nil) where n is the number of binaries written.
// If fsys contains no matching files the function prints a warning and returns (0, nil).
func UnpackClients(fsys fs.FS, dataDir string, w io.Writer) (int, error) {
	destDir := filepath.Join(dataDir, "binaries")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return 0, fmt.Errorf("mkdir %s: %w", destDir, err)
	}

	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return 0, fmt.Errorf("read embed FS: %w", err)
	}

	count := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// Only copy files that look like sigilc binaries; skip README etc.
		if !isBinaryName(e.Name()) {
			continue
		}
		src, err := fsys.Open(e.Name())
		if err != nil {
			return count, fmt.Errorf("open %s: %w", e.Name(), err)
		}
		dest := filepath.Join(destDir, e.Name())
		if err := writeFile(src, dest); err != nil {
			_ = src.Close()
			return count, fmt.Errorf("write %s: %w", dest, err)
		}
		_ = src.Close()
		count++
		fmt.Fprintf(w, "  unpacked %s\n", dest)
	}

	if count == 0 {
		fmt.Fprintf(w, "warning: no bundled sigilc binaries found; "+
			"drop binaries into %s manually or set binary_source in server.yaml\n", destDir)
	}
	return count, nil
}

// isBinaryName reports whether name looks like a sigilc binary
// (starts with "sigilc-" to exclude README and similar files).
func isBinaryName(name string) bool {
	return len(name) > 7 && name[:7] == "sigilc-"
}

func writeFile(src fs.File, dest string) error {
	data, err := io.ReadAll(src)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".sigil-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, dest)
}
