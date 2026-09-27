//go:build !windows

package output

import (
	"os"
	"testing"
)

func checkMode(t *testing.T, info os.FileInfo, want os.FileMode) {
	t.Helper()
	if got := info.Mode().Perm(); got != want {
		t.Errorf("file mode: got %o, want %o", got, want)
	}
}
