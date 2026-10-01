// Package proc runs the programs that certfolds and certfoldc start from their
// configuration: those of the exec DNS provider and of on_change. It imports
// only the standard library and, on Windows, golang.org/x/sys, so that certfoldc
// can use it without linking the ACME client.
package proc

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// outputLimit caps the output of one run that Run keeps. The end of the
// output, where errors usually are, is kept.
const outputLimit = 4 << 10

// Run runs argv[0] with the arguments argv[1:] and returns nil if it exits 0.
//
// The program runs directly, never through a shell, with an empty stdin, and
// with the environment and in the working directory of this process. Run
// returns the last 4 KiB it wrote to stdout and stderr, prefixed with "..."
// when it wrote more, and keeps no more than that, however much it writes.
//
// When timeout passes or ctx ends while the program runs, Run kills it along
// with every process it started: on Unix its process group, which it leads,
// and on Windows a job object. A process outside them is not killed: one that
// calls setsid on Unix, or one that a service such as the Task Scheduler
// starts on the program's behalf. The error is then "timed out after
// <timeout>" or context.Cause(ctx). On Windows the job also kills them all
// when this process exits during the run.
//
// The processes a program leaves behind when it exits by itself keep running.
// Once it has exited or been killed, waitDelay bounds how long they may keep
// its output open. Run then closes the output, which may end them at their
// next write, and returns exec.ErrWaitDelay if the program exited 0.
//
// The error holds neither the arguments nor the output; it names argv[0] when
// the program cannot be started.
func Run(ctx context.Context, argv []string, timeout, waitDelay time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeoutCause(ctx, timeout, fmt.Errorf("timed out after %s", timeout))
	defer cancel()
	out := &tailWriter{}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	// One writer for both, so exec serializes the writes to it.
	cmd.Stdout, cmd.Stderr = out, out
	cmd.WaitDelay = waitDelay
	release, err := start(ctx, cmd)
	if err == nil {
		err = cmd.Wait()
		release()
	}
	if err != nil && !errors.Is(err, exec.ErrWaitDelay) && ctx.Err() != nil {
		// Wait reports the killed program's exit status, not why it was
		// killed: the timeout, or ctx ending.
		err = context.Cause(ctx)
	}
	tail := out.tail
	if out.truncated {
		tail = append([]byte("..."), tail...)
	}
	return tail, err
}

// tailWriter keeps the last outputLimit bytes written to it.
type tailWriter struct {
	tail      []byte
	truncated bool
}

func (w *tailWriter) Write(p []byte) (int, error) {
	w.tail = append(w.tail, p...)
	if extra := len(w.tail) - outputLimit; extra > 0 {
		w.tail = append(w.tail[:0], w.tail[extra:]...)
		w.truncated = true
	}
	return len(p), nil
}
