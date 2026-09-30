//go:build !windows

package store

import (
	"os"
	"path/filepath"
	"testing"
)

// Reopening a database tightens its main file, -wal and -shm when they were
// loosened in the meantime. New files are created 0600, so only a reopen
// shows that Open protects the files it finds.
func TestOpenTightensLoosenedFilesOnReopen(t *testing.T) {
	path := filepath.Join(privateDirectory(t), "sigils.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		// A clean close removes both; leave loose empty ones behind as a
		// crash or another tool would.
		if err := os.WriteFile(path+suffix, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path+suffix, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	db, err = Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer db.Close()
	for _, suffix := range []string{"", "-wal", "-shm"} {
		assertPrivateSQLiteFile(t, path+suffix)
	}
}

func makeSQLiteDirectoryBroad(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

func assertPrivateSQLiteFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode for %s = %#o, want 0600", path, got)
	}
}

func assertPrivateSQLiteDirectory(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("mode for %s = %#o, want 0700", path, got)
	}
}

// directorySecurity describes the mode of the directory at path.
func directorySecurity(t *testing.T, path string) string {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().String()
}
