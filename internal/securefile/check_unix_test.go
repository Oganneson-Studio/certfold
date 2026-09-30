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
// user owns: its owner may have put files in it, so the error says to remove
// it first. With mode 0700 the owner is the only problem; with 0755 the error
// reports both at once. As root, the test gives a directory to nobody;
// otherwise /, root's with mode 0755, stands for one with both problems.
func TestCheckPrivateDirectoryRefusesAnotherOwner(t *testing.T) {
	const remove = "remove it, so that it is created again"
	if os.Geteuid() != 0 {
		checkErrorContains(t, "/", remove, fmt.Sprintf(`chown %d "/"`, os.Geteuid()), `chmod 700 "/"`)
		return
	}
	dir := t.TempDir()
	if err := os.Chown(dir, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	chown := fmt.Sprintf(`chown 0 "%s"`, dir)
	for _, mode := range []os.FileMode{0o700, 0o755} {
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if mode == 0o700 {
			checkErrorContains(t, dir, remove, chown)
		} else {
			checkErrorContains(t, dir, remove, chown+"\n  "+`chmod 700 "`+dir+`"`)
		}
	}
}

// checkErrorContains fails unless CheckPrivateDirectory refuses dir with an
// error that contains every one of wants.
func checkErrorContains(t *testing.T, dir string, wants ...string) {
	t.Helper()
	err := CheckPrivateDirectory(dir)
	if err == nil {
		t.Fatalf("%s passed", dir)
	}
	for _, want := range wants {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%v\nwant it to contain %q", err, want)
		}
	}
}
