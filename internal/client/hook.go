package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"time"

	"github.com/Oganneson-Studio/certfold/internal/logging"
	"github.com/Oganneson-Studio/certfold/internal/proc"
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

// runHook runs argv, the on_change program of the certificate certName, and
// returns nil if it exits 0.
//
// How it runs, through proc.Run:
//   - argv is executed directly, never through a shell. It comes only from
//     client.yaml; the server's responses, the certificate name included, are
//     only used to look up that configuration and never choose the program,
//     its arguments or where it runs.
//   - The program inherits the environment of certfoldc with nothing added, gets
//     an empty stdin, and runs in the working directory of certfoldc: / or
//     System32 when it runs as a service.
//   - hookTimeout (2 minutes) bounds one run; when it expires the program is
//     killed along with the processes it started. Once it has exited or been
//     killed, WaitDelay (5 seconds) bounds how long a process it started may
//     keep its output open. Both are package variables only so tests can
//     shorten them.
//   - The timeout is added to ctx, which must end with the daemon: the ctx
//     of Run, or context.Background before Run starts. After Run returns,
//     callers keep passing its cancelled ctx, so a program started then is
//     killed at once instead of outliving the daemon. Stopping the
//     daemon kills the program and the processes it started instead of
//     waiting up to hookTimeout for them, since the service stop waits for
//     Run to return. An IPC caller that disconnects must not kill it, so ctx
//     is never that of an IPC request. A killed run is a failure; the
//     program runs again after the next start.
//   - The processes a program leaves behind when it exits by itself keep
//     running.
//   - Callers hold pullMu, so at most one program runs at a time, and never
//     while outputs are being written.
//
// Errors and logs follow the exec DNS provider:
//   - The error names only the certificate and the exit status or the
//     timeout, plus argv[0] when the program cannot be started. certfoldc status
//     shows it as the last error.
//   - argv[1:] and the program's output never appear in the error: the
//     arguments may hold credentials, and the output may repeat them.
//   - Every failed run is logged as the event "on_change failed". Only the
//     last 4 KiB of the output are kept, and the event holds them as a
//     logging.Private value: the service log shows them, the events and the
//     Windows event log do not. The output of a run that succeeds is not
//     logged.
//   - A program that exits 0 succeeds even if a process it started still
//     holds the output when WaitDelay expires. The output is closed then,
//     which may end that process on its next write, so this is logged as the
//     event "on_change output held open", naming only the certificate.
func runHook(ctx context.Context, certName string, argv []string) error {
	out, err := proc.Run(ctx, argv, hookTimeout, hookWaitDelay)
	if err == nil {
		return nil
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		// The program exited 0, but a process it started still held its
		// output when WaitDelay expired. Closing the output may end that
		// process on its next write, so leave a trace of it.
		slog.Warn("on_change output held open", "cert", certName)
		return nil
	}
	slog.Warn("on_change failed", "cert", certName, "error", err, "output", logging.Private(out))
	return fmt.Errorf("on_change of certificate %s: %w", certName, err)
}
