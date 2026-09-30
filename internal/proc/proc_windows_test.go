package proc

import (
	"os/exec"
	"testing"
	"time"
)

// TestRunKillsTheProcessesWhenThisProcessExits covers a process that exits
// during a run without ending it, as sigils does when shutdown gives up on an
// issuance: on Windows the job kills the program and what it started. Unix
// has no such guarantee.
func TestRunKillsTheProcessesWhenThisProcessExits(t *testing.T) {
	child := newHeartbeat(t)

	// The process exits once the child of the program it runs is running.
	if err := exec.Command(testArgv(t, "exit-during-run")[0]).Run(); err != nil {
		t.Fatalf("the process that runs the program: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if child.alive() {
		t.Fatal("a process that a program started is still running after the process that ran the program exited")
	}
}
