//go:build !windows

package ipc

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// Listen opens a Unix domain socket at path and returns the net.Listener.
// The socket directory is created if it doesn't exist; permissions are set to
// 0660. If path is empty, DefaultServerSocket() is used. Listen fails while
// another daemon answers on path; a socket file nobody answers on is left over
// from a daemon that did not shut down cleanly and is replaced. Anything else
// at path is left alone, so a mistyped ipc_socket cannot delete a file.
func Listen(path string) (net.Listener, error) {
	if path == "" {
		path = DefaultServerSocket()
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("ipc mkdir %s: %w", dir, err)
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&fs.ModeSocket == 0 {
		return nil, fmt.Errorf("ipc listen %s: path exists and is not a socket", path)
	}
	// Unlike Dial, this does not check the owner: whoever owns the socket,
	// an answer means it is taken and no answer means it is left over.
	conn, err := net.Dial("unix", path)
	if err == nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ipc listen %s: another daemon is already running on this socket", path)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("ipc listen %s: %w", path, err)
	}
	// Remove stale socket file.
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("ipc listen %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("ipc chmod %s: %w", path, err)
	}
	return l, nil
}

// Dial connects to the Unix domain socket at path and refuses a socket that
// neither root nor the effective user of this process owns, as Dial does on
// Windows for a pipe that LocalSystem or Administrators does not own. Another
// local user who could create the socket while the daemon is stopped would
// otherwise answer in its place. The owner is that of the socket file: Lstat
// does not follow a symbolic link put in its place.
func Dial(path string) (net.Conn, error) {
	if path == "" {
		path = DefaultServerSocket()
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if err := checkSocketOwner(info, os.Geteuid()); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return net.Dial("unix", path)
}

// checkSocketOwner accepts a socket file owned by root or by euid.
func checkSocketOwner(info fs.FileInfo, euid int) error {
	owner := info.Sys().(*syscall.Stat_t).Uid
	if owner != 0 && int(owner) != euid {
		return fmt.Errorf("socket is owned by uid %d rather than root or uid %d; another program may have taken the socket path while the daemon was not running", owner, euid)
	}
	return nil
}

// DefaultServerSocket returns the default sigils IPC socket path.
func DefaultServerSocket() string { return "/var/run/sigil/sigils.sock" }

// DefaultClientSocket returns the default sigilc IPC socket path.
func DefaultClientSocket() string {
	return "/var/run/sigil/sigilc.sock"
}
