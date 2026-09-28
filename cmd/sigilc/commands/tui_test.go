package commands

import (
	"strings"
	"testing"
)

// TestTUIFailsWhenDaemonIsNotRunning covers sigilc run without a command: with
// no daemon to read, it reports that rather than opening an empty TUI.
func TestTUIFailsWhenDaemonIsNotRunning(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"--ipc", missingIPCSocket(t)})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "daemon is not running") {
		t.Fatalf("sigilc returned %v, want a daemon-not-running error", err)
	}
}
