//go:build !windows

package client

import (
	"os"
	"testing"
)

// checkPrivate fails unless only the owner may access path: mode 0600.
func checkPrivate(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("file mode: got %o, want 600", got)
	}
}

// usersReadableDir returns a directory for the store; file modes alone decide
// who can read the files in it.
func usersReadableDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}
