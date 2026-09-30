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
		// exec cancels only before it has waited for the program, so the
		// group ID is still the program's own process ID.
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	return func() {}, cmd.Start()
}
