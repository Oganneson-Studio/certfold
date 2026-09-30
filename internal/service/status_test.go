package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/ipc"
)

// testSocket returns an IPC endpoint no daemon listens on.
func testSocket(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return fmt.Sprintf(`\\.\pipe\sigil-service-test-%d`, time.Now().UnixNano())
	}
	// Unix socket paths are length-limited; keep this one short.
	dir, err := os.MkdirTemp("", "sigil")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

// TestRunningStatusProbesTheDaemon covers `service status` while systemd
// restarts a daemon that fails at start: kardianos reports the activating
// unit as running, so the status says so only when the daemon answers, and
// otherwise why it does not and where to read more.
func TestRunningStatusProbesTheDaemon(t *testing.T) {
	socket := testSocket(t)
	got := runningStatus(RoleClient, socket)
	if !strings.HasPrefix(got, "Running (not answering on "+socket+": ") || !strings.HasSuffix(got, "; see "+serviceLog("sigilc")+")") {
		t.Errorf("status without a daemon = %q, want not answering on %s", got, socket)
	}

	l, err := ipc.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	if conn, err := ipc.Dial(socket); errors.Is(err, os.ErrPermission) && runtime.GOOS == "windows" {
		t.Skip("the pipe admits only SYSTEM and elevated administrators")
	} else if err == nil {
		_ = conn.Close()
	}
	if got := runningStatus(RoleClient, socket); got != "Running" {
		t.Errorf("status with a daemon = %q, want Running", got)
	}
}

// A pipe that stays busy, as one whose daemon has stopped accepting, does
// not answer. Dial gives up after two seconds.
func TestRunningStatusOfBusyPipe(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("a Unix socket does not stay busy")
	}
	socket := testSocket(t)
	l, err := ipc.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	// Nothing accepts, so the pipe stays busy.
	got := runningStatus(RoleClient, socket)
	if strings.Contains(got, "needs root or an elevated administrator") {
		t.Skip("the pipe admits only SYSTEM and elevated administrators")
	}
	if !strings.HasPrefix(got, "Running (not answering on "+socket+": ") {
		t.Errorf("status of a busy pipe = %q, want not answering", got)
	}
}

// TestRunningStatusCannotCheckWithoutPermission covers `service status` run
// by a user who may not open the endpoint of the daemon: that says nothing
// about whether the daemon answers, so the status says it cannot check, and
// what checking needs.
func TestRunningStatusCannotCheckWithoutPermission(t *testing.T) {
	var socket string
	if runtime.GOOS == "windows" {
		// Opening a directory as a pipe is denied, as a pipe whose DACL
		// leaves the user out is.
		socket = t.TempDir()
	} else {
		if os.Geteuid() == 0 {
			t.Skip("root may open any socket")
		}
		dir := filepath.Join(t.TempDir(), "private")
		if err := os.Mkdir(dir, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		socket = filepath.Join(dir, "s.sock")
	}
	got := runningStatus(RoleClient, socket)
	if !strings.HasPrefix(got, "Running (cannot check the daemon on "+socket+": ") || !strings.HasSuffix(got, "; checking it needs root or an elevated administrator)") {
		t.Errorf("status of an endpoint the user may not open = %q, want that it cannot check", got)
	}
}
