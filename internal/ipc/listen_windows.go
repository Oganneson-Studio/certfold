//go:build windows

package ipc

import (
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
)

const (
	serverPipe = `\\.\pipe\sigil-server`
	clientPipe = `\\.\pipe\sigil-client`
	// SDDL: local system + built-in administrators only.
	pipeSddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
)

// Listen opens a Windows named pipe and returns the net.Listener.
func Listen(path string) (net.Listener, error) {
	if path == "" {
		path = DefaultServerSocket()
	}
	cfg := &winio.PipeConfig{SecurityDescriptor: pipeSddl}
	l, err := winio.ListenPipe(path, cfg)
	if err != nil {
		return nil, fmt.Errorf("ipc listen pipe %s: %w", path, err)
	}
	return l, nil
}

// Dial connects to the named pipe at path.
func Dial(path string) (net.Conn, error) {
	if path == "" {
		path = DefaultServerSocket()
	}
	return winio.DialPipe(path, nil)
}

// DefaultServerSocket returns the default sigils IPC named pipe.
func DefaultServerSocket() string { return serverPipe }

// DefaultClientSocket returns the default sigilc IPC named pipe.
func DefaultClientSocket() string { return clientPipe }
