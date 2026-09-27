package commands

import (
	"bytes"
	"os"
	"strings"
	"testing"

	internalsvc "github.com/Oganneson-Studio/sigil/internal/service"
)

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
	if got != "C:/sigil-test" {
		t.Fatalf("data dir = %q, want the configured server.data_dir", got)
	}

	raw = bytes.Replace(raw, []byte("  data_dir: \"C:/sigil-test\"\n"), nil, 1)
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
