//go:build !windows

package output

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/Oganneson-Studio/sigil/internal/config"
)

// TestReconcileRestoresMode covers outputs whose permission bits were changed
// after they were written: a key made readable by others, and a certificate
// made private. Their content matches, so the bits are restored in place, and
// no change is reported.
func TestReconcileRestoresMode(t *testing.T) {
	b := makeBundle(t)
	dir := t.TempDir()
	key := config.OutputSpec{Format: "pem-key", Path: filepath.Join(dir, "key.pem")}
	cert := config.OutputSpec{Format: "pem-cert", Path: filepath.Join(dir, "cert.pem")}
	mustReconcile(t, b, key, cert)
	keyBefore, certBefore := fileState(t, key.Path), fileState(t, cert.Path)
	if err := os.Chmod(key.Path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cert.Path, 0o600); err != nil {
		t.Fatal(err)
	}

	if mustReconcile(t, b, key, cert) {
		t.Fatal("changed modes reported a change")
	}
	checkMode(t, key.Path, 0o600)
	checkMode(t, cert.Path, 0o644)
	checkUntouched(t, key.Path, keyBefore)
	checkUntouched(t, cert.Path, certBefore)
	checkContent(t, b, key)
	checkContent(t, b, cert)
}

// TestReconcileReportsFailedRepair covers an output whose content matches but
// whose owner cannot be set in place: only root may give a file to another
// user. The chown error must be returned with the output's path, and no
// change reported.
func TestReconcileReportsFailedRepair(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may chown")
	}
	b := makeBundle(t)
	spec := config.OutputSpec{Format: "pem-cert", Path: filepath.Join(t.TempDir(), "cert.pem")}
	mustReconcile(t, b, spec)
	before := fileState(t, spec.Path)

	spec.Owner = "root"
	changed, err := Reconcile(b, []config.OutputSpec{spec})
	if err == nil || changed || !strings.Contains(err.Error(), spec.Path) {
		t.Fatalf("Reconcile = %v, %v; want an error with %s and no change", changed, err, spec.Path)
	}
	checkUntouched(t, spec.Path, before)
}

// TestReconcileErrorOfFailedOwnershipIsStable covers an owner that the
// temporary file of an output may not be given: a process that is not root
// may not give a file to root.
func TestReconcileErrorOfFailedOwnershipIsStable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may chown")
	}
	dir := t.TempDir()
	spec := config.OutputSpec{Format: "pem-cert", Path: filepath.Join(dir, "cert.pem"), Owner: "root"}
	if text := reconcileErrorTwice(t, makeBundle(t), spec); !strings.HasPrefix(text, "write "+spec.Path+": ") {
		t.Fatalf("error = %s, want it to name the output", text)
	}
	checkNoTemps(t, dir)
}

// TestReconcileRestoresOwnership covers an output whose owner, then group,
// was changed after it was written. Its content matches, so each is restored
// in place, and no change is reported. Changing either needs root.
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
		if mustReconcile(t, b, spec) {
			t.Fatalf("an output with another %s reported a change", change.what)
		}
		checkOwnership(t, spec.Path, uid, gid)
		checkUntouched(t, spec.Path, before)
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
