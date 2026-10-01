package commands

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	internalsvc "github.com/Oganneson-Studio/sigil/internal/service"
)

// TestServiceUsesTheConfigOfTheOtherCommands covers `sigils service install`
// in a shell that sets SIGILS_CONFIG: the service must start with the file
// every other command reads, not with the platform default.
func TestServiceUsesTheConfigOfTheOtherCommands(t *testing.T) {
	fromEnv := filepath.Join(t.TempDir(), "env.yaml")
	t.Setenv("SIGILS_CONFIG", fromEnv)
	if got := serverSvcConfig(NewRootCmd()).ConfigPath; got != fromEnv {
		t.Errorf("service config path = %q, want $SIGILS_CONFIG %q", got, fromEnv)
	}
	flag := filepath.Join(t.TempDir(), "flag.yaml")
	cmd := NewRootCmd()
	if err := cmd.PersistentFlags().Set("config", flag); err != nil {
		t.Fatal(err)
	}
	if got := serverSvcConfig(cmd).ConfigPath; got != flag {
		t.Errorf("service config path = %q, want --config %q", got, flag)
	}
}

func TestServiceDataDirUsesConfiguredDataDirWithoutCredentials(t *testing.T) {
	path := writeManagementTestConfig(t, "  []\n")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The installing shell usually lacks the DNS credentials the daemon uses.
	raw = bytes.ReplaceAll(raw, []byte("${SIGIL_TEST_"), []byte("${SIGIL_TEST_UNSET_"))
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := internalsvc.Config{Role: internalsvc.RoleServer, ConfigPath: path}

	got, err := serviceDataDir(cfg)
	if err != nil {
		t.Fatalf("serviceDataDir: %v", err)
	}
	if got != absPath("/sigil-test") {
		t.Fatalf("data dir = %q, want the configured server.data_dir", got)
	}

	// A relative data_dir would put the binaries under the directory the
	// install runs in, not where the service looks for them.
	relative := bytes.Replace(raw, []byte(absPath("/sigil-test")), []byte("sigil-test"), 1)
	if err := os.WriteFile(path, relative, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := serviceDataDir(cfg); err == nil || !strings.Contains(err.Error(), `server.data_dir: must be an absolute path, got "sigil-test"`) {
		t.Fatalf("relative data_dir error = %v", err)
	}

	raw = bytes.Replace(raw, []byte("  data_dir: \""+absPath("/sigil-test")+"\"\n"), nil, 1)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := serviceDataDir(cfg); err == nil || !strings.Contains(err.Error(), "server.data_dir is not set") {
		t.Fatalf("missing data_dir error = %v", err)
	}

	// The error must say why installing a service reads server.yaml at all.
	cfg.ConfigPath = path + ".missing"
	if _, err := serviceDataDir(cfg); err == nil || !strings.Contains(err.Error(), "read server.data_dir to unpack sigilc binaries") {
		t.Fatalf("unreadable config error = %v", err)
	}
}
