//go:build !windows

package output

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/Oganneson-Studio/sigil/internal/config"
)

// TestReconcileRestoresMode covers outputs whose permission bits were changed
// after they were written: a key made readable by others, and a certificate
// made private.
func TestReconcileRestoresMode(t *testing.T) {
	b := makeBundle(t)
	dir := t.TempDir()
	key := config.OutputSpec{Format: "pem-key", Path: filepath.Join(dir, "key.pem")}
	cert := config.OutputSpec{Format: "pem-cert", Path: filepath.Join(dir, "cert.pem")}
	mustReconcile(t, b, key, cert)
	if err := os.Chmod(key.Path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cert.Path, 0o600); err != nil {
		t.Fatal(err)
	}

	if !mustReconcile(t, b, key, cert) {
		t.Fatal("changed modes reported no change")
	}
	checkMode(t, key.Path, 0o600)
	checkMode(t, cert.Path, 0o644)
}

// TestReconcileRestoresOwnership covers an output whose owner, then group,
// was changed after it was written. Changing either needs root.
func TestReconcileRestoresOwnership(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chown needs root")
	}
	nobody, err := user.Lookup("nobody")
	if err != nil {
		t.Skipf("no user nobody: %v", err)
	}
	// The name of the primary group of nobody differs between distributions.
	group, err := user.LookupGroupId(nobody.Gid)
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.Atoi(nobody.Uid)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.Atoi(nobody.Gid)
	if err != nil {
		t.Fatal(err)
	}

	b := makeBundle(t)
	spec := config.OutputSpec{
		Format: "pem-key",
		Path:   filepath.Join(t.TempDir(), "key.pem"),
		Owner:  nobody.Username,
		Group:  group.Name,
	}
	if !mustReconcile(t, b, spec) {
		t.Fatal("a missing output reported no change")
	}
	checkOwnership(t, spec.Path, uid, gid)
	before := fileState(t, spec.Path)
	if mustReconcile(t, b, spec) {
		t.Fatal("an output with the configured owner and group was rewritten")
	}
	checkUntouched(t, spec.Path, before)

	for _, change := range []struct {
		what     string
		uid, gid int
	}{
		{what: "owner", uid: 0, gid: -1},
		{what: "group", uid: -1, gid: 0},
	} {
		if err := os.Lchown(spec.Path, change.uid, change.gid); err != nil {
			t.Fatal(err)
		}
		if !mustReconcile(t, b, spec) {
			t.Fatalf("an output with another %s reported no change", change.what)
		}
		checkOwnership(t, spec.Path, uid, gid)
	}
}

func checkOwnership(t *testing.T, path string, uid, gid int) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if int(stat.Uid) != uid || int(stat.Gid) != gid {
		t.Errorf("%s is owned by %d:%d, want %d:%d", path, stat.Uid, stat.Gid, uid, gid)
	}
}
