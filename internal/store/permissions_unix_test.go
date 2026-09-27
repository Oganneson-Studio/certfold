//go:build !windows

package store

import (
	"os"
	"testing"
)

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
