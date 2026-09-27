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
// from a daemon that did not shut down cleanly and is replaced.
func Listen(path string) (net.Listener, error) {
	if path == "" {
		path = DefaultServerSocket()
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("ipc mkdir %s: %w", dir, err)
	}
	conn, err := Dial(path)
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

// Dial connects to the Unix domain socket at path.
func Dial(path string) (net.Conn, error) {
	if path == "" {
		path = DefaultServerSocket()
	}
	return net.Dial("unix", path)
}

// DefaultServerSocket returns the default sigils IPC socket path.
func DefaultServerSocket() string { return "/var/run/sigil/sigils.sock" }

// DefaultClientSocket returns the default sigilc IPC socket path.
func DefaultClientSocket() string {
	return "/var/run/sigil/sigilc.sock"
}
