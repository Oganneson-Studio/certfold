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
	return fmt.Sprintf(`\\.\pipe\sigil-ipc-test-%d`, time.Now().UnixNano())
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
		if !closeListener(t, l) {
			return
		}
		<-done
		for _, conn := range conns {
			_ = conn.Close()
		}
	})
}

// closeListener closes l and reports whether Close returned within five
// seconds. go-winio v0.6.2 can block in Close forever when its cancellation
// meets a ConnectNamedPipe that Accept has only just issued, which is exactly
// when a test that has just dialed cleans up. Upstream fixed it in 7e8af9b,
// which needs Go 1.26.
func closeListener(t *testing.T, l net.Listener) bool {
	t.Helper()
	closed := make(chan struct{})
	go func() {
		_ = l.Close()
		close(closed)
	}()
	select {
	case <-closed:
		return true
	case <-time.After(5 * time.Second):
		t.Log("pipe listener Close did not return within 5s (go-winio v0.6.2 close race); leaving it behind")
		return false
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
}
