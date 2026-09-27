//go:build !windows

package output

import (
	"os"
	"testing"
)

func checkMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("file mode: got %o, want %o", got, want)
	}
}

// outputDir returns a directory for output files; file modes alone decide
// who can read them.
func outputDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}
