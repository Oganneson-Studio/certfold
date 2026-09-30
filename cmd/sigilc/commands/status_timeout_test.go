package commands

import (
	"errors"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/ipc"
)

// TestStatusGivesUpOnADaemonThatDoesNotAnswer covers an IPC endpoint that
// accepts connections and never answers: sigilc status fails after
// statusTimeout, as a refresh of the TUI does, rather than after the 5
// minutes of the IPC client, which install.sh, running it until the daemon
// answers, would wait 15 times over.
func TestStatusGivesUpOnADaemonThatDoesNotAnswer(t *testing.T) {
	socket := missingIPCSocket(t)
	l, err := ipc.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range held {
			_ = conn.Close()
		}
	})
	if _, err := ipc.NewClient(socket); err != nil {
		if runtime.GOOS == "windows" && errors.Is(err, os.ErrPermission) {
			t.Skip("the sigilc pipe admits only SYSTEM and elevated administrators")
		}
		t.Fatal(err)
	}

	start := time.Now()
	_, err = runSigilcErr(t, "--ipc", socket, "status")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("sigilc status succeeded against a daemon that does not answer")
	}
	if elapsed < statusTimeout || elapsed > statusTimeout+10*time.Second {
		t.Errorf("sigilc status failed after %s (%v), want after about %s", elapsed, err, statusTimeout)
	}
}
