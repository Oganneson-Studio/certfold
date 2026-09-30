package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/ipc"
)

func TestEnsureEnrollmentConfig_CreatesInitialConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "client.yaml")
	name, created, err := ensureEnrollmentConfig(path, "web-1", "https://sigil.example.com")
	if err != nil {
		t.Fatalf("ensureEnrollmentConfig: %v", err)
	}
	if name != "web-1" || !created {
		t.Fatalf("name = %q, created = %t; want web-1, created", name, created)
	}
	cfg, err := config.LoadClient(path)
	if err != nil {
		t.Fatalf("load generated config: %v", err)
	}
	if cfg.Client.Name != "web-1" || cfg.Client.ServerURL != "https://sigil.example.com" {
		t.Fatalf("generated config = %+v", cfg.Client)
	}
	if cfg.Client.DataDir != config.DefaultClientDataDir() {
		t.Fatalf("generated data_dir = %q, want client default %q", cfg.Client.DataDir, config.DefaultClientDataDir())
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got&0o077 != 0 {
			t.Fatalf("generated config mode = %#o, want no group/other permissions", got)
		}
	}
}

// A client.yaml that names another client or server URL is not replaced; the
// error says where it is, so an operator who meant to replace it can.
func TestEnsureEnrollmentConfig_RejectsTokenMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.yaml")
	if _, _, err := ensureEnrollmentConfig(path, "web-1", "https://sigil.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ensureEnrollmentConfig(path, "web-2", "https://sigil.example.com"); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("mismatched client name: error = %v, want one that names %s", err, path)
	}
	if _, _, err := ensureEnrollmentConfig(path, "web-1", "https://other.example.com"); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("mismatched server URL: error = %v, want one that names %s", err, path)
	}
	if _, created, err := ensureEnrollmentConfig(path, "web-1", "https://sigil.example.com"); err != nil || created {
		t.Fatalf("matching token: created = %t, error = %v; want the client.yaml there", created, err)
	}
}

func TestClientIPCSocketUsesConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.yaml")
	configured := filepath.Join(t.TempDir(), "configured.sock")
	raw := fmt.Sprintf("client:\n  name: web-1\n  server_url: https://sigil.example.com\n  ipc_socket: %q\n", configured)
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCmd()
	if err := cmd.PersistentFlags().Set("config", path); err != nil {
		t.Fatal(err)
	}
	if got := clientIPCSocket(cmd); got != configured {
		t.Fatalf("socket = %q, want configured path %q", got, configured)
	}
}

// TestClientIPCSocketDoesNotNeedTheServiceEnvironment is the client side of
// the server's "locating the daemon must not require the credentials it
// expands": client.yaml may take a PKCS#12 password from a variable that only
// the service's environment sets (/etc/sysconfig/sigilc), which sudo does not
// pass to the CLI. The configured ipc_socket must still be found, rather than
// the platform default, where no daemon listens.
func TestClientIPCSocketDoesNotNeedTheServiceEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.yaml")
	configured := filepath.Join(t.TempDir(), "configured.sock")
	output := filepath.Join(t.TempDir(), "api.p12")
	raw := fmt.Sprintf(`client:
  name: web-1
  server_url: https://sigil.example.com
  ipc_socket: %q
certificates:
  api:
    outputs:
      - format: pkcs12
        path: %q
        password: ${SIGIL_PROBE_UNSET_P12_PASSWORD}
`, configured, output)
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCmd()
	if err := cmd.PersistentFlags().Set("config", path); err != nil {
		t.Fatal(err)
	}
	if got := clientIPCSocket(cmd); got != configured {
		t.Fatalf("socket with an unset variable elsewhere in client.yaml = %q, want configured %q", got, configured)
	}
}

// TestServiceUsesTheConfigOfTheOtherCommands covers `sigilc service install`
// in a shell that sets SIGILC_CONFIG: the service must start with the file
// every other command reads, not with the platform default.
func TestServiceUsesTheConfigOfTheOtherCommands(t *testing.T) {
	fromEnv := filepath.Join(t.TempDir(), "env.yaml")
	t.Setenv("SIGILC_CONFIG", fromEnv)
	if got := clientSvcConfig(NewRootCmd()).ConfigPath; got != fromEnv {
		t.Errorf("service config path = %q, want $SIGILC_CONFIG %q", got, fromEnv)
	}
	flag := filepath.Join(t.TempDir(), "flag.yaml")
	cmd := NewRootCmd()
	if err := cmd.PersistentFlags().Set("config", flag); err != nil {
		t.Fatal(err)
	}
	if got := clientSvcConfig(cmd).ConfigPath; got != flag {
		t.Errorf("service config path = %q, want --config %q", got, flag)
	}
}

func TestClientIPCSocketExplicitFlagWins(t *testing.T) {
	cmd := NewRootCmd()
	explicit := filepath.Join(t.TempDir(), "explicit.sock")
	if err := cmd.PersistentFlags().Set("config", filepath.Join(t.TempDir(), "missing.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := cmd.PersistentFlags().Set("ipc", explicit); err != nil {
		t.Fatal(err)
	}
	if got := clientIPCSocket(cmd); got != explicit {
		t.Fatalf("socket = %q, want explicit path %q", got, explicit)
	}
}

// missingIPCSocket returns an IPC endpoint no daemon listens on.
func missingIPCSocket(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return fmt.Sprintf(`\\.\pipe\sigil-client-missing-%d-%d`, os.Getpid(), time.Now().UnixNano())
	}
	return filepath.Join(t.TempDir(), "missing.sock")
}

func TestStatusFailsWhenDaemonIsNotRunning(t *testing.T) {
	socket := missingIPCSocket(t)
	for _, args := range [][]string{{"status"}, {"status", "--json"}} {
		cmd := NewRootCmd()
		cmd.SetArgs(append([]string{"--ipc", socket}, args...))
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "daemon is not running") {
			t.Fatalf("sigilc %v returned %v, want a daemon-not-running error", args, err)
		}
	}
}

func TestClientIPCSocketFallsBackToClientDefault(t *testing.T) {
	cmd := NewRootCmd()
	if err := cmd.PersistentFlags().Set("config", filepath.Join(t.TempDir(), "missing.yaml")); err != nil {
		t.Fatal(err)
	}
	if got := clientIPCSocket(cmd); got != ipc.DefaultClientSocket() {
		t.Fatalf("socket = %q, want client default %q", got, ipc.DefaultClientSocket())
	}
}
