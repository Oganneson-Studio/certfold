//go:build !windows

package ipc

import (
	"net"
	"os"
	"path/filepath"
	"strings"
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
