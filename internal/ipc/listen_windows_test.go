package ipc

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func testPipeName() string {
	return fmt.Sprintf(`\\.\pipe\sigil-ipc-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
}

// acceptAll accepts connections on l until the test ends, because a pipe
// takes a client only while its server waits in Accept. It closes l and the
// accepted connections at cleanup.
func acceptAll(t *testing.T, l net.Listener) {
	t.Helper()
	done := make(chan struct{})
	var conns []net.Conn
	go func() {
		defer close(done)
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			conns = append(conns, conn)
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		<-done
		for _, conn := range conns {
			_ = conn.Close()
		}
	})
}

// listenTaken calls Listen on name, which another listener holds, and returns
// its error. The owner of that pipe can be read only while it waits in
// Accept, which acceptAll starts in a goroutine, so Listen is called again
// while it finds every instance of the pipe busy.
func listenTaken(t *testing.T, name string) error {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		l, err := Listen(name)
		if err == nil {
			l.Close()
			t.Fatal("Listen took a pipe name another listener holds")
		}
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A program that takes the pipe name before the service starts keeps the
// daemon from starting; the error names the pipe and its owner.
func TestListenNamesOwnerOfTakenPipe(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	name := testPipeName()
	l, err := winio.ListenPipe(name, &winio.PipeConfig{
		SecurityDescriptor: "O:" + user.User.Sid.String() + "D:P(A;;GA;;;WD)",
	})
	if err != nil {
		t.Fatal(err)
	}
	acceptAll(t, l)

	err = listenTaken(t, name)
	want := fmt.Sprintf("ipc listen pipe %s: pipe is owned by %s rather than LocalSystem or Administrators", name, user.User.Sid)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Listen error = %v, want %s", err, want)
	}
}

// A pipe that never waits for a client has no instance to open, so its
// owner cannot be read.
func TestListenReportsTakenPipeWithUnreadableOwner(t *testing.T) {
	name := testPipeName()
	l, err := winio.ListenPipe(name, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	_, err = Listen(name)
	want := fmt.Sprintf("ipc listen pipe %s: another process holds the pipe name, and its owner cannot be read", name)
	if err == nil || !strings.Contains(err.Error(), want) || !errors.Is(err, windows.ERROR_PIPE_BUSY) {
		t.Fatalf("Listen error = %v, want %s: all pipe instances are busy", err, want)
	}
}

func TestListenRefusesPipeOfRunningDaemon(t *testing.T) {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	if admin, err := windows.Token(0).IsMember(admins); err != nil || !admin {
		t.Skip("only SYSTEM and elevated administrators can read the owner of the pipe of Listen")
	}
	name := testPipeName()
	l, err := Listen(name)
	if err != nil {
		t.Fatal(err)
	}
	acceptAll(t, l)

	err = listenTaken(t, name)
	if want := fmt.Sprintf("ipc listen pipe %s: another daemon is already running on this pipe", name); err == nil || err.Error() != want {
		t.Fatalf("second Listen error = %v, want %s", err, want)
	}
}

func TestCheckPipeOwner(t *testing.T) {
	tests := []struct {
		name  string
		owner string // SDDL owner component; empty means none
		ok    bool
	}{
		{name: "LocalSystem", owner: "O:SY", ok: true},
		{name: "Administrators", owner: "O:BA", ok: true},
		{name: "a local user", owner: "O:S-1-5-21-1111111111-2222222222-3333333333-1001"},
		{name: "Users", owner: "O:BU"},
		{name: "Everyone", owner: "O:WD"},
		{name: "Authenticated Users", owner: "O:AU"},
		{name: "LocalService", owner: "O:LS"},
		{name: "NetworkService", owner: "O:NS"},
		{name: "service account", owner: "O:S-1-5-80-0"},
		{name: "no owner"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tt.owner + pipeSddl)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkPipeOwner(sd); (err == nil) != tt.ok {
				t.Fatalf("checkPipeOwner = %v, want accepted %t", err, tt.ok)
			}
		})
	}
}

func TestCheckPipeConnRefusesConnectionWithoutHandle(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	if err := checkPipeConn(client); err == nil {
		t.Fatal("checkPipeConn accepted a connection whose pipe owner it cannot read")
	}
}

func TestDialAcceptsPipeOfListen(t *testing.T) {
	name := testPipeName()
	l, err := Listen(name)
	if err != nil {
		t.Fatal(err)
	}
	acceptAll(t, l)

	conn, err := Dial(name)
	if errors.Is(err, os.ErrPermission) {
		t.Skip("the pipe admits only SYSTEM and elevated administrators")
	}
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()
}

func TestDialRefusesPipeOwnedByAnotherAccount(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	// A low-privilege process that takes the name first owns the pipe as
	// itself and can let anyone connect.
	name := testPipeName()
	l, err := winio.ListenPipe(name, &winio.PipeConfig{
		SecurityDescriptor: "O:" + user.User.Sid.String() + "D:P(A;;GA;;;WD)",
	})
	if err != nil {
		t.Fatal(err)
	}
	acceptAll(t, l)

	conn, err := Dial(name)
	if err == nil {
		conn.Close()
		t.Fatal("Dial accepted a pipe owned by an unprivileged account")
	}
	if !strings.Contains(err.Error(), "rather than LocalSystem or Administrators") {
		t.Fatalf("Dial error = %v, want an owner error", err)
	}

	// Commands report the refusal through NewClient, which names the
	// operation once.
	if _, err := NewClient(name); err == nil || strings.Count(err.Error(), "ipc dial") != 1 {
		t.Fatalf("NewClient error = %v, want the owner error with one ipc dial prefix", err)
	}
}
