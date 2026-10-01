package commands

import (
	"strings"
	"testing"
	"time"
)

// TestTUIFailsWhenDaemonIsNotRunning covers certfoldc run without a command: with
// no daemon to read, it reports that rather than opening an empty TUI. A TUI
// opened by mistake may not return on its own, so the test gives up waiting.
func TestTUIFailsWhenDaemonIsNotRunning(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"--ipc", missingIPCSocket(t)})
	done := make(chan error, 1)
	go func() { done <- cmd.Execute() }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "daemon is not running") {
			t.Fatalf("certfoldc returned %v, want a daemon-not-running error", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("certfoldc did not return within 10s: it opened the TUI")
	}
}
