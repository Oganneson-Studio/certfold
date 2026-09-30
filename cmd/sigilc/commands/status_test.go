package commands

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/ipc"
)

// unreachableIPCSocket returns an IPC endpoint that exists but that no
// daemon answers on, so a dial fails with an error other than a missing
// endpoint or a refused connection, as it does for a user who may not open
// the socket of a running daemon.
func unreachableIPCSocket(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		// Opening a directory as a pipe is denied.
		return t.TempDir()
	}
	// A path below a regular file names no socket, and not because it is
	// missing.
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(file, "s.sock")
}

// TestCommandsReportWhyTheDaemonIsUnreachable covers the commands that talk
// to the daemon when the dial fails for another reason than that nothing
// listens, such as a socket the user may not open: saying that the daemon is
// not running would send the operator to start a daemon that runs.
func TestCommandsReportWhyTheDaemonIsUnreachable(t *testing.T) {
	socket := unreachableIPCSocket(t)
	for _, args := range [][]string{{}, {"status"}, {"status", "--json"}, {"reload"}, {"fetch"}, {"events"}} {
		root := NewRootCmd()
		root.SetArgs(append([]string{"--ipc", socket}, args...))
		done := make(chan error, 1)
		go func() { done <- root.Execute() }()
		select {
		case err := <-done:
			if err == nil || strings.Contains(err.Error(), "not running") || strings.Count(err.Error(), "ipc dial") != 1 {
				t.Errorf("sigilc %v: error = %v, want the dial error, once, without a claim that the daemon is not running", args, err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("sigilc %v did not return within 10s: it opened the TUI", args)
		}
	}
}

// TestStatusJSONReportsEveryError covers `sigilc status --json` when the
// daemon answers the state request with an error: the output says so, as it
// does when the dial fails.
func TestStatusJSONReportsEveryError(t *testing.T) {
	socket := missingIPCSocket(t)
	l, err := ipc.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := ipc.NewServer(ipc.ServerDeps{Client: &ipc.ClientControlDeps{
		State: func(context.Context) (ipc.ClientState, error) { return ipc.ClientState{}, errors.New("state broken") },
	}})
	t.Cleanup(func() { _ = srv.Close() })
	go func() { _ = srv.Serve(l) }()
	if _, err := ipc.NewClient(socket); err != nil {
		if runtime.GOOS == "windows" && errors.Is(err, os.ErrPermission) {
			t.Skip("the sigilc pipe admits only SYSTEM and elevated administrators")
		}
		t.Fatal(err)
	}

	for _, s := range []string{socket, missingIPCSocket(t)} {
		printed, err := runSigilcErr(t, "--ipc", s, "status", "--json")
		if err == nil {
			t.Fatalf("status --json against %s succeeded", s)
		}
		var out struct {
			Error string `json:"error"`
		}
		if jsonErr := json.Unmarshal([]byte(printed), &out); jsonErr != nil || out.Error != err.Error() {
			t.Errorf("status --json against %s printed %q, want the error %q as JSON", s, printed, err)
		}
	}
}
