//go:build unix

package commands

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Oganneson-Studio/certfold/internal/ipc"
)

// A client.yaml this user may not read, as the private one is to all but
// root, counts as none: certfoldc service status run without root goes on to
// the default socket, which it cannot open either, and says that checking
// the daemon needs root.
func TestClientIPCSocketOfUnreadableConfigIsTheDefault(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a file of mode 0000")
	}
	path := filepath.Join(t.TempDir(), "client.yaml")
	raw := "client:\n  name: web-1\n  server_url: https://certfold.example.com\n  ipc_socket: /run/certfold/custom.sock\n"
	if err := os.WriteFile(path, []byte(raw), 0); err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCmd()
	if err := cmd.PersistentFlags().Set("config", path); err != nil {
		t.Fatal(err)
	}
	if got, err := clientIPCSocket(cmd); err != nil || got != ipc.DefaultClientSocket() {
		t.Fatalf("socket = %q, %v; want default %q", got, err, ipc.DefaultClientSocket())
	}
}
