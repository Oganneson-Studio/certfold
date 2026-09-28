package client

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"time"
)

// Bounds on one run of an on_change program. They are variables only so tests
// can shorten them.
var (
	// hookTimeout bounds one run; when it expires the program is killed.
	hookTimeout = 2 * time.Minute
	// hookWaitDelay bounds how long the program's output may stay open after
	// it exits or is killed, typically because a process it started still
	// holds it.
	hookWaitDelay = 5 * time.Second
)

// hookOutputLimit caps the program output kept for the log. The end of the
// output, where errors usually are, is kept.
const hookOutputLimit = 4 << 10

// runHook runs argv, the on_change program of the certificate certName, and
// returns nil if it exits 0.
//
// How it runs:
//   - argv is executed directly, never through a shell. It comes only from
//     client.yaml; the server's responses, the certificate name included, are
//     only used to look up that configuration and never choose the program,
//     its arguments or where it runs.
//   - The program inherits the environment of sigilc with nothing added, gets
//     an empty stdin, and runs in the working directory of sigilc: / or
//     System32 when it runs as a service.
//   - hookTimeout (2 minutes) bounds one run; when it expires the program is
//     killed. Once it has exited or been killed, WaitDelay (5 seconds) bounds
//     how long a process it started may keep its output open. Both are
//     package variables only so tests can shorten them.
//   - The timeout is added to ctx, which must end with the daemon: the ctx
//     of Run, or context.Background while Run is not running. Stopping the
//     daemon kills the program instead of waiting up to hookTimeout for it,
//     since the service stop waits for Run to return. An IPC caller that
//     disconnects must not kill it, so ctx is never that of an IPC request.
//     A killed run is a failure; the program runs again after the next start.
//   - Callers hold pullMu, so at most one program runs at a time, and never
//     while outputs are being written.
//
// Errors and logs follow the exec DNS provider:
//   - The error names only the certificate and the exit status or the
//     timeout, plus argv[0] when the program cannot be started. sigilc status
//     shows it as the last error.
//   - argv[1:] and the program's output never appear in the error: the
//     arguments may hold credentials, and the output may repeat them.
//   - Only the last 4 KiB of the output are kept, and they are logged only
//     when the run fails.
//   - A program that exits 0 succeeds even if a process it started still
//     holds the output when WaitDelay expires. The output is closed then,
//     which may end that process on its next write, so this is logged,
//     naming only the certificate.
func runHook(ctx context.Context, certName string, argv []string) error {
	ctx, cancel := context.WithTimeoutCause(ctx, hookTimeout, fmt.Errorf("timed out after %s", hookTimeout))
	defer cancel()
	out := &tailWriter{}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	// One writer for both, so exec serializes the writes to it.
	cmd.Stdout, cmd.Stderr = out, out
	cmd.WaitDelay = hookWaitDelay
	err := cmd.Run()
	if err == nil {
		return nil
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		// The program exited 0, but a process it started still held its
		// output when WaitDelay expired. Closing the output may end that
		// process on its next write, so leave a trace of it.
		log.Printf("sigilc: on_change of certificate %s exited 0, but a process it started still held its output after %s; the output was closed", certName, hookWaitDelay)
		return nil
	}
	if ctx.Err() != nil {
		// Wait reports the killed program's exit status, not why it was
		// killed: the timeout, or ctx ending with the daemon.
		err = context.Cause(ctx)
	}
	if len(out.tail) > 0 {
		tail := out.tail
		if out.truncated {
			tail = append([]byte("..."), tail...)
		}
		log.Printf("sigilc: on_change of certificate %s failed: %v; output: %q", certName, err, tail)
	}
	return fmt.Errorf("on_change of certificate %s: %w", certName, err)
}

// tailWriter keeps the last hookOutputLimit bytes written to it.
type tailWriter struct {
	tail      []byte
	truncated bool
}

func (w *tailWriter) Write(p []byte) (int, error) {
	w.tail = append(w.tail, p...)
	if extra := len(w.tail) - hookOutputLimit; extra > 0 {
		w.tail = append(w.tail[:0], w.tail[extra:]...)
		w.truncated = true
	}
	return len(p), nil
}
