package commands

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Oganneson-Studio/certfold/internal/ipc"
)

// TestCertRenewNotWaitedForMayStillFinish covers certfolds cert renew that stops
// waiting, at Ctrl-C or when the IPC client gives up after five minutes: the
// daemon finishes a renewal that has started and stores the certificate, so
// the error says so rather than suggesting that nothing happened.
func TestCertRenewNotWaitedForMayStillFinish(t *testing.T) {
	socket := testIPCSocket(t)
	l, err := ipc.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := ipc.NewServer(ipc.ServerDeps{Certificates: &ipc.CertificateControlDeps{
		Renew: func(ctx context.Context, _ string) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}})
	t.Cleanup(func() { _ = srv.Close() })
	go func() { _ = srv.Serve(l) }()
	if _, err := ipc.NewClient(socket); err != nil {
		skipWithoutPipeAccess(t, err)
		t.Fatal(err)
	}

	// A deadline, as the IPC client's, and a cancellation, as Ctrl-C's.
	const want = "; the renewal may still finish in the daemon: see `certfolds events` or `certfolds cert show api`"
	for _, cause := range []error{context.DeadlineExceeded, context.Canceled} {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		if cause == context.Canceled {
			ctx, cancel = context.WithCancel(context.Background())
			time.AfterFunc(200*time.Millisecond, cancel)
		}
		root := NewRootCmd()
		root.SetArgs([]string{"--ipc", socket, "cert", "renew", "api"})
		err := root.ExecuteContext(ctx)
		cancel()
		if !errors.Is(err, cause) || !strings.HasSuffix(err.Error(), want) {
			t.Errorf("cert renew that stopped waiting: error = %v, want %v followed by %q", err, cause, want)
		}
	}
}
