//go:build !windows

package securefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheckPrivateDirectory covers the mode and the owner of a directory: the
// user of the process must own it, and its mode must give the group and others
// nothing. The check changes neither.
func TestCheckPrivateDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivateDirectory(dir); err != nil {
		t.Fatalf("a private directory: %v", err)
	}

	for _, mode := range []os.FileMode{0o750, 0o705, 0o1777} {
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		err := CheckPrivateDirectory(dir)
		if err == nil || !strings.Contains(err.Error(), `chmod 700 "`+dir+`"`) {
			t.Errorf("mode %#o: %v, want an error that says to chmod 700 %s", mode, err, dir)
		}
		if info, statErr := os.Stat(dir); statErr != nil || info.Mode()&os.ModePerm != mode&os.ModePerm {
			t.Errorf("mode %#o: the check changed the mode to %v (%v)", mode, info.Mode(), statErr)
		}
	}

	if err := CheckPrivateDirectory(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing directory: %v, want os.ErrNotExist", err)
	}
}

// TestCheckPrivateDirectoryRefusesAnotherOwner covers a directory that another
// user owns, even with mode 0700: its owner may have put files in it. As root,
// the test gives a directory to nobody; otherwise / stands for one.
func TestCheckPrivateDirectoryRefusesAnotherOwner(t *testing.T) {
	dir := "/"
	if os.Geteuid() == 0 {
		dir = t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(dir, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	err := CheckPrivateDirectory(dir)
	want := fmt.Sprintf(`chown %d "%s"`, os.Geteuid(), dir)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("%v, want an error that says to run %s", err, want)
	}
}
