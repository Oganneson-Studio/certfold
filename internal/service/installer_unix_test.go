//go:build !windows

package service

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
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

// TestUnpackClientsRefusesDataDirOthersMayRead covers a data_dir that exists
// but is not private, as sigils would refuse it at start: UnpackClients must
// refuse it too, write nothing into it, and leave its mode, since it may be a
// directory like /var/lib.
func TestUnpackClientsRefusesDataDirOthersMayRead(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "sigils")
	if err := os.Mkdir(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fsys := fstest.MapFS{"sigilc-linux-amd64": &fstest.MapFile{Data: []byte("x")}}
	_, err := UnpackClients(fsys, dataDir, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), `chmod 700 "`+dataDir+`"`) {
		t.Fatalf("UnpackClients error = %v, want one that says to chmod 700 %s", err, dataDir)
	}
	info, err := os.Stat(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Errorf("data_dir mode = %#o, want it left 0755", got)
	}
	if entries, err := os.ReadDir(dataDir); err != nil || len(entries) != 0 {
		t.Errorf("UnpackClients left %v (%v) in the data_dir it refused", entries, err)
	}
}
