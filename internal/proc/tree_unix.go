//go:build unix

package proc

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// start starts cmd as the leader of a new process group, which the processes
// it starts join, and makes the cancellation of cmd kill the whole group.
// release does nothing on Unix: the processes left in the group when the
// program exits by itself keep running.
func start(_ context.Context, cmd *exec.Cmd) (release func(), err error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// The group ID is the program's process ID. exec usually cancels
		// while the program runs, but when ctx ends as the program exits it
		// may cancel after it has waited for it: the kill then reaches the
		// members left in the group, or none, which ESRCH reports.
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	return func() {}, cmd.Start()
}
