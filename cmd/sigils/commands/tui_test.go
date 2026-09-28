package commands

import (
	"strings"
	"testing"
	"time"
)

// Without a running daemon, sigils reports that instead of opening a TUI
// that shows nothing.
func TestServerTUIRequiresRunningDaemon(t *testing.T) {
	root := NewRootCmd()
	root.SetArgs([]string{"--ipc", testIPCSocket(t)})
	done := make(chan error, 1)
	go func() { done <- root.Execute() }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "ipc unavailable") {
			t.Fatalf("sigils without a daemon: error = %v, want ipc unavailable", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("sigils without a daemon did not return; it opened the TUI")
	}
}
