//go:build !windows

package server

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The edited server.yaml keeps the mode and owner of the file it replaces: a
// group that reads the file, or an owner other than the daemon's account,
// must not lose access to it.
func TestCertificateEditKeepsModeAndOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	writeRuntimeConfig(t, path, initialRuntimeConfig)
	// Another owner than the one a new file gets, where this process may
	// give one: root may give any, others only a group they are in.
	uid, gid := os.Getuid(), os.Getgid()
	if uid == 0 {
		uid, gid = 65534, 65534
	} else if groups, err := os.Getgroups(); err == nil {
		for _, group := range groups {
			if group != gid {
				gid = group
				break
			}
		}
	}
	if err := os.Chown(path, uid, gid); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	runtime := newServerConfigRuntime(path, parseRuntimeConfig(t, initialRuntimeConfig), func() {}, publishNow)

	if err := runtime.AddCertificate(context.Background(), wwwSpec); err != nil {
		t.Fatalf("AddCertificate: %v", err)
	}
	assertCertificates(t, runtime, path, "api-prod", "www")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	if info.Mode().Perm() != 0o640 || int(stat.Uid) != uid || int(stat.Gid) != gid {
		t.Errorf("edited server.yaml has mode %o and owner %d:%d, want 640 and %d:%d",
			info.Mode().Perm(), stat.Uid, stat.Gid, uid, gid)
	}
}
