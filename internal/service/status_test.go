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
