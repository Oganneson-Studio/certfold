package securefile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestWriteFileErrorOfFailedReplaceIsStable covers a file that cannot be
// replaced, here because a directory is in its place. The same failure must
// read the same each time and name no temporary file, whose random name
// would make a daemon that logs an error only when its text changes log it
// every time.
func TestWriteFileErrorOfFailedReplaceIsStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certs.json")
	// No file can be renamed over a directory that is not empty.
	if err := os.MkdirAll(filepath.Join(path, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	var texts [2]string
	for i := range texts {
		err := WriteFile(path, []byte("private"))
		if err == nil {
			t.Fatalf("WriteFile %d succeeded, want the failed replace", i+1)
		}
		texts[i] = err.Error()
	}
	if texts[0] != texts[1] {
		t.Fatalf("the same failure reads differently:\n%s\n%s", texts[0], texts[1])
	}
	if strings.Contains(texts[0], ".sigil-private-") || !strings.HasPrefix(texts[0], "replace "+path+": ") {
		t.Fatalf("error = %s, want it to name %s and no temporary file", texts[0], path)
	}
	if left, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".sigil-private-*")); err != nil || len(left) != 0 {
		t.Fatalf("temporary files left: %v, %v", left, err)
	}
}

// TestWithoutTempName covers the errors of operations on a temporary file:
// the *os.PathError or *os.LinkError that names the file is left out, and
// its cause kept; other errors are kept whole.
func TestWithoutTempName(t *testing.T) {
	cause := syscall.ENOSPC
	other := errors.New("no unused temporary file name in /var/lib/sigil")
	for _, tc := range []struct {
		err  error
		want error
	}{
		{&os.PathError{Op: "write", Path: "/var/lib/sigil/.sigil-private-1", Err: cause}, cause},
		{&os.LinkError{Op: "rename", Old: "/var/lib/sigil/.sigil-private-1", New: "/var/lib/sigil/certs.json", Err: cause}, cause},
		{other, other},
	} {
		if got := withoutTempName(tc.err); got != tc.want {
			t.Errorf("withoutTempName(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
