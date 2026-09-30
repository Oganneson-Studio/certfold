//go:build linux

package service

import (
	"net"
	"strings"
	"syscall"
	"testing"
)

// TestRunningStatusOfBusySocket is the Linux side of
// TestRunningStatusOfBusyPipe: a socket whose daemon has stopped accepting
// fills its backlog, and a dial then fails with EAGAIN, which reports
// Timeout(); the daemon does not answer.
func TestRunningStatusOfBusySocket(t *testing.T) {
	socket := testSocket(t)
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: socket}); err != nil {
		t.Fatal(err)
	}
	// A backlog of 0 queues one connection; nothing accepts it.
	if err := syscall.Listen(fd, 0); err != nil {
		t.Fatal(err)
	}
	queued, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = queued.Close() })

	if got := runningStatus(RoleClient, socket); !strings.HasPrefix(got, "Running (not answering on "+socket+": ") {
		t.Errorf("status of a busy socket = %q, want not answering", got)
	}
}
