//go:build windows

package ipc

import (
	"errors"
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const (
	serverPipe = `\\.\pipe\certfold-server`
	clientPipe = `\\.\pipe\certfold-client`
	// DACL: local system + built-in administrators only.
	pipeSddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
)

// Listen opens a Windows named pipe and returns the net.Listener.
//
// Dial trusts a pipe only when LocalSystem or BUILTIN\Administrators owns it.
// Without an explicit owner, a pipe belongs to the default owner of the
// creating token: LocalSystem for the services, and normally Administrators
// for an elevated administrator. The environment that starts the process can
// change that default, though; under Git Bash, MSYS makes it the user's own
// SID. A process with administrator rights, LocalSystem included, therefore
// names Administrators as the owner, so the owner does not depend on how the
// daemon was started. A low-privilege process cannot claim either owner.
func Listen(path string) (net.Listener, error) {
	if path == "" {
		path = DefaultServerSocket()
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, fmt.Errorf("ipc listen pipe %s: %w", path, err)
	}
	// IsMember counts enabled groups only, so the deny-only Administrators
	// group of a non-elevated token does not qualify. The zero token is what
	// CheckTokenMembership documents for the caller: it checks the thread's
	// impersonation token, or a copy of the process token when there is none.
	admin, err := windows.Token(0).IsMember(admins)
	if err != nil {
		return nil, fmt.Errorf("ipc listen pipe %s: %w", path, err)
	}
	sddl := pipeSddl
	if admin {
		sddl = "O:BA" + pipeSddl
	}
	l, err := winio.ListenPipe(path, &winio.PipeConfig{SecurityDescriptor: sddl})
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		err = pipeTaken(path)
	}
	if err != nil {
		return nil, fmt.Errorf("ipc listen pipe %s: %w", path, err)
	}
	return l, nil
}

// pipeTaken explains why creating the pipe at path was denied: a pipe of that
// name exists. Its owner tells another daemon from a program that took the
// name first, which keeps the daemon from starting. The owner can be read
// only while the pipe waits for a client and its DACL lets this process read
// it.
func pipeTaken(path string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("another process holds the pipe name, and its owner cannot be read: %w", err)
	}
	if err := checkPipeOwner(sd); err != nil {
		return err
	}
	return errors.New("another daemon is already running on this pipe")
}

// Dial connects to the named pipe at path and refuses a pipe that LocalSystem
// or BUILTIN\Administrators does not own. While a daemon is stopped, any local
// process could create its pipe and answer in its place, for example with an
// enrollment token whose install command runs a script of its choosing; the
// owner shows whether a privileged process created the pipe. A daemon running
// as another account, such as a virtual service account, is refused on
// purpose.
func Dial(path string) (net.Conn, error) {
	if path == "" {
		path = DefaultServerSocket()
	}
	conn, err := winio.DialPipe(path, nil)
	if err != nil {
		return nil, err
	}
	if err := checkPipeConn(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return conn, nil
}

// checkPipeConn checks the owner of the pipe that conn is connected to.
func checkPipeConn(conn net.Conn) error {
	f, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return fmt.Errorf("cannot read the pipe owner of a %T connection", conn)
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read pipe owner: %w", err)
	}
	return checkPipeOwner(sd)
}

// checkPipeOwner accepts a pipe security descriptor owned by LocalSystem or
// BUILTIN\Administrators.
func checkPipeOwner(sd *windows.SECURITY_DESCRIPTOR) error {
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read pipe owner: %w", err)
	}
	if owner == nil {
		return errors.New("pipe has no owner")
	}
	if !owner.IsWellKnown(windows.WinLocalSystemSid) && !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return fmt.Errorf("pipe is owned by %s rather than LocalSystem or Administrators; another program may have taken the pipe name while the daemon was not running", owner)
	}
	return nil
}

// DefaultServerSocket returns the default certfolds IPC named pipe.
func DefaultServerSocket() string { return serverPipe }

// DefaultClientSocket returns the default certfoldc IPC named pipe.
func DefaultClientSocket() string { return clientPipe }
