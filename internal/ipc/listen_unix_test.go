//go:build !windows

package ipc

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func testSocketPath(t *testing.T) string {
	t.Helper()
	// Unix socket paths are length-limited; keep this one short.
	dir, err := os.MkdirTemp("", "sigil")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

func TestListenRefusesSocketOfRunningDaemon(t *testing.T) {
	path := testSocketPath(t)
	running, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer running.Close()

	second, err := Listen(path)
	if err == nil {
		second.Close()
		t.Fatal("a second Listen took over the socket of a running daemon")
	}
	if !strings.Contains(err.Error(), "already running") {
		t.Fatalf("second Listen error = %v, want an already running error", err)
	}
	conn, err := Dial(path)
	if err != nil {
		t.Fatalf("the running daemon's socket no longer answers: %v", err)
	}
	conn.Close()
}

func TestListenKeepsPathThatIsNotSocket(t *testing.T) {
	for _, tt := range []struct {
		name   string
		create func(path string) error
	}{
		{name: "regular file", create: func(path string) error { return os.WriteFile(path, []byte("keep"), 0o600) }},
		{name: "empty directory", create: func(path string) error { return os.Mkdir(path, 0o700) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := testSocketPath(t)
			if err := tt.create(path); err != nil {
				t.Fatal(err)
			}
			if l, err := Listen(path); err == nil {
				l.Close()
				t.Fatal("Listen replaced a path that is not a socket")
			} else if !strings.Contains(err.Error(), "not a socket") {
				t.Fatalf("Listen error = %v, want a not a socket error", err)
			}
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatalf("the existing path is gone: %v", err)
			}
			if info.Mode()&os.ModeSocket != 0 {
				t.Fatal("the existing path was replaced by a socket")
			}
		})
	}
}

// Other local users must not reach the admin API.
func TestListenSocketModeIs0660(t *testing.T) {
	path := testSocketPath(t)
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o660 {
		t.Fatalf("socket mode = %#o, want 0660", got)
	}
}

// Dial trusts a socket that root or the caller owns: a daemon runs as root,
// or as the user who runs the CLI.
func TestCheckSocketOwner(t *testing.T) {
	path := testSocketPath(t)
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	owner := int(info.Sys().(*syscall.Stat_t).Uid)
	if err := checkSocketOwner(info, owner); err != nil {
		t.Fatalf("socket of the caller refused: %v", err)
	}
	if owner == 0 {
		if err := checkSocketOwner(info, 1000); err != nil {
			t.Fatalf("socket of root refused: %v", err)
		}
		return
	}
	if err := checkSocketOwner(info, owner+1); err == nil || !strings.Contains(err.Error(), "rather than root") {
		t.Fatalf("socket of uid %d accepted for uid %d: %v", owner, owner+1, err)
	}
}

// Only root can give a socket to another user, so this test runs as root
// only: on the Linux verification server with sudo.
func TestDialRefusesSocketOfAnotherUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("only root can create a socket another user owns")
	}
	path := testSocketPath(t)
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	// nobody on most systems; any uid but root's will do.
	if err := os.Lchown(path, 65534, 65534); err != nil {
		t.Fatal(err)
	}

	conn, err := Dial(path)
	if err == nil {
		conn.Close()
		t.Fatal("Dial accepted a socket owned by another user")
	}
	if !strings.Contains(err.Error(), path+": socket is owned by uid 65534 rather than root") {
		t.Fatalf("Dial error = %v, want an owner error naming the socket", err)
	}
	if _, err := NewClient(path); err == nil || strings.Count(err.Error(), "ipc dial") != 1 {
		t.Fatalf("NewClient error = %v, want the owner error with one ipc dial prefix", err)
	}
}

func TestListenReplacesStaleSocket(t *testing.T) {
	path := testSocketPath(t)
	// A daemon that died without closing its listener leaves the socket file
	// behind with nobody answering on it.
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stale socket file: %v", err)
	}

	l, err := Listen(path)
	if err != nil {
		t.Fatalf("Listen over a stale socket: %v", err)
	}
	defer l.Close()
	conn, err := Dial(path)
	if err != nil {
		t.Fatalf("dial the new listener: %v", err)
	}
	conn.Close()
}
