//go:build unix

package commands

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/ipc"
)

// TestCertRenewInterruptEndsTheWaitNotTheProcess covers Ctrl-C while
// sigils cert renew waits: the signal must end the wait, so that the error
// can say that the renewal may still finish, rather than kill the process.
// Without the handler, SIGINT kills the test binary.
func TestCertRenewInterruptEndsTheWaitNotTheProcess(t *testing.T) {
	socket := testIPCSocket(t)
	l, err := ipc.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	waiting := make(chan struct{})
	srv := ipc.NewServer(ipc.ServerDeps{Certificates: &ipc.CertificateControlDeps{
		Renew: func(ctx context.Context, _ string) error {
			once.Do(func() { close(waiting) })
			<-ctx.Done()
			return ctx.Err()
		},
	}})
	t.Cleanup(func() { _ = srv.Close() })
	go func() { _ = srv.Serve(l) }()

	root := NewRootCmd()
	root.SetArgs([]string{"--ipc", socket, "cert", "renew", "api"})
	done := make(chan error, 1)
	go func() { done <- root.Execute() }()
	select {
	case <-waiting:
	case err := <-done:
		t.Fatalf("cert renew returned before the daemon received the request: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the daemon did not receive the renewal")
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "the renewal may still finish in the daemon") {
			t.Fatalf("cert renew after Ctrl-C: error = %v, want the cancellation and that the renewal may still finish", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Ctrl-C did not end the wait of cert renew")
	}
}
