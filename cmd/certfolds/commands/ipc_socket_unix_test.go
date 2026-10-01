//go:build unix

package commands

import (
	"os"
	"testing"

	"github.com/Oganneson-Studio/certfold/internal/ipc"
)

// A server.yaml this user may not read counts as none, as for certfolds service
// status run without root: such a user may not open the socket of the daemon
// either, which the error of the default one says.
func TestServerIPCSocketOfUnreadableConfigIsTheDefault(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a file of mode 0000")
	}
	path := writeManagementTestConfig(t, "  []\n")
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	cmd := NewRootCmd()
	if err := cmd.PersistentFlags().Set("config", path); err != nil {
		t.Fatal(err)
	}
	if got, err := serverIPCSocket(cmd); err != nil || got != ipc.DefaultServerSocket() {
		t.Fatalf("socket = %q, %v; want default %q", got, err, ipc.DefaultServerSocket())
	}
}
