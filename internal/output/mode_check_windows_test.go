//go:build windows

package output

import (
	"os"
	"testing"
)

// checkMode on Windows: Unix permission bits are not enforced by NTFS.
// We only verify the file exists (caller already has the os.FileInfo).
func checkMode(t *testing.T, info os.FileInfo, want os.FileMode) {
	t.Helper()
	_ = want
	_ = info
	// No-op: Windows ACL semantics differ from Unix mode bits.
}
