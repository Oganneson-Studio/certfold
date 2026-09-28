package client

import (
	"context"
	"os/exec"
)

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
//
// This is a stub: it runs argv to completion under ctx and returns the result.
func runHook(ctx context.Context, certName string, argv []string) error {
	return exec.CommandContext(ctx, argv[0], argv[1:]...).Run()
}
