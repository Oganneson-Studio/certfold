//go:build !windows

package service

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
)

// TestUnpackClientsCreatesPrivateDataDir covers `sigils service install
// --with-clients` before the daemon has first run: data_dir does not exist
// yet, and one created with the default mode would let a local user put a
// binary of their own into binaries/ for the install scripts to hand out.
func TestUnpackClientsCreatesPrivateDataDir(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "sigils")
	fsys := fstest.MapFS{"sigilc-linux-amd64": &fstest.MapFile{Data: []byte("x")}}
	if _, err := UnpackClients(fsys, dataDir, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("data_dir mode = %#o, want 0700", got)
	}
}
