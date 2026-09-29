package service

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	ksvc "github.com/kardianos/service"

	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/securefile"
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
	sc, err := buildServiceConfig(cfg)
	if err != nil {
		return nil, err
	}
	return ksvc.New(d, sc)
}

func buildServiceConfig(cfg Config) (*ksvc.Config, error) {
	name, displayName, desc, cfgDefault := roleAttrs(cfg.Role)

	configPath := cfg.ConfigPath
	if configPath == "" {
		configPath = cfgDefault
	}
	// The service manager starts the daemon in a working directory of its
	// own, / under systemd and System32 under the SCM, where a relative path
	// names no file: the daemon would fail at every start.
	configPath, err := filepath.Abs(configPath)
	if err != nil {
		return nil, fmt.Errorf("resolve config path: %w", err)
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
		sc.Option = ksvc.KeyValue{
			"SystemdScript": systemdUnit,
		}
	case "darwin":
		sc.Option = ksvc.KeyValue{
			"KeepAlive": true,
		}
	case "windows":
		// Match systemd's Restart=on-failure. Windows repeats the only
		// recovery action for every later failure, so a crash or a failed
		// start is always retried; a normal stop exits 0 and is not a failure.
		// The reset period clears the failure count after a day without one.
		sc.Option = ksvc.KeyValue{
			"OnFailure":              "restart",
			"OnFailureDelayDuration": "10s",
			"OnFailureResetPeriod":   24 * 60 * 60,
		}
	}

	return sc, nil
}

// systemdUnit replaces the unit kardianos writes by default, which restarts a
// failed daemon only after 120 seconds. A daemon that keeps failing, such as
// one whose configuration does not load, is restarted every 5 seconds without
// end: without StartLimit settings, systemd's default limit of 5 starts in 10
// seconds is never reached. An earlier install keeps its unit: kardianos
// refuses to install over an existing service, so the service has to be
// uninstalled and installed again. The template syntax is that of kardianos
// v1.3.0.
const systemdUnit = `[Unit]
Description={{Description}}
ConditionFileIsExecutable={{Path | cmdEscape}}
After=network-online.target
Wants=network-online.target

[Service]
ExecStart={{Path | cmdEscape}}{{range Arguments}} {{. | cmd}}{{end}}
Restart=on-failure
RestartSec=5
EnvironmentFile=-/etc/sysconfig/{{Name}}

[Install]
WantedBy=multi-user.target
`

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
	return install(svc, cfg.Role)
}

// install registers svc, the service of role. kardianos refuses to install
// over an existing service, and then the error says how to go on.
func install(svc ksvc.Service, role Role) error {
	if err := svc.Install(); err != nil {
		if _, statusErr := svc.Status(); !errors.Is(statusErr, ksvc.ErrNotInstalled) {
			name, _, _, _ := roleAttrs(role)
			return fmt.Errorf("install service: %w; to install it anew, run `%s service uninstall` first", err, name)
		}
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

// StatusText returns a human-readable service status string. The service
// manager reports a daemon that it keeps restarting as running: kardianos
// maps systemd's activating to running, and the SCM's start pending as well.
// So a running service is running only if its daemon answers on socket, its
// IPC endpoint.
func StatusText(d Daemon, cfg Config, socket string) (string, error) {
	svc, err := New(d, cfg)
	if err != nil {
		return "", err
	}
	// kardianos reports a service that is not installed, or in systemd's
	// failed state, as an error.
	st, err := svc.Status()
	if err != nil {
		return "", fmt.Errorf("query status: %w", err)
	}
	if st != ksvc.StatusRunning {
		return "Stopped", nil
	}
	return runningStatus(cfg.Role, socket), nil
}

// runningStatus reports a service the manager reports as running: "Running"
// when its daemon answers on socket, and why not otherwise.
func runningStatus(role Role, socket string) string {
	conn, err := ipc.Dial(socket)
	if err != nil {
		name, _, _, _ := roleAttrs(role)
		return fmt.Sprintf("Running (not answering on %s: %v; see %s)", socket, err, serviceLog(name))
	}
	_ = conn.Close()
	return "Running"
}

// serviceLog says where the log of the service name is: the log of a daemon
// that fails at start says why.
func serviceLog(name string) string {
	switch runtime.GOOS {
	case "windows":
		return "the Application event log, source " + name
	case "darwin":
		return "/var/log/" + name + ".err.log"
	default:
		return "journalctl -u " + name
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

// UnpackClients copies sigilc binaries from fsys into dataDir/binaries/.
// Returns (n, nil) where n is the number of binaries written.
// If fsys contains no matching files the function prints a warning and returns (0, nil).
func UnpackClients(fsys fs.FS, dataDir string, w io.Writer) (int, error) {
	// The service is installed before it first runs, so data_dir may not
	// exist yet. Created with the default permissions, it would let a local
	// user put a binary of their own there for the install scripts to hand
	// out to every new client.
	if err := securefile.EnsurePrivateDirectory(dataDir); err != nil {
		return 0, fmt.Errorf("private directory %s: %w", dataDir, err)
	}
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
		fmt.Fprintf(w, "warning: this sigils bundles no sigilc binaries; for the install scripts to download them, "+
			"put them into %s as sigilc-<os>-<arch>, with .exe for windows\n", destDir)
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
