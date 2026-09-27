package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/ipc"
)

func TestEnsureEnrollmentConfig_CreatesInitialConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "client.yaml")
	name, err := ensureEnrollmentConfig(path, "web-1", "https://sigil.example.com")
	if err != nil {
		t.Fatalf("ensureEnrollmentConfig: %v", err)
	}
	if name != "web-1" {
		t.Fatalf("name = %q, want web-1", name)
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

func TestEnsureEnrollmentConfig_RejectsTokenMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.yaml")
	if _, err := ensureEnrollmentConfig(path, "web-1", "https://sigil.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureEnrollmentConfig(path, "web-2", "https://sigil.example.com"); err == nil {
		t.Fatal("expected mismatched client name to fail")
	}
	if _, err := ensureEnrollmentConfig(path, "web-1", "https://other.example.com"); err == nil {
		t.Fatal("expected mismatched server URL to fail")
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

func TestClientIPCSocketFallsBackToClientDefault(t *testing.T) {
	cmd := NewRootCmd()
	if err := cmd.PersistentFlags().Set("config", filepath.Join(t.TempDir(), "missing.yaml")); err != nil {
		t.Fatal(err)
	}
	if got := clientIPCSocket(cmd); got != ipc.DefaultClientSocket() {
		t.Fatalf("socket = %q, want client default %q", got, ipc.DefaultClientSocket())
	}
}
