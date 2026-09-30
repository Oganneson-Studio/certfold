//go:build windows

package agent

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/Oganneson-Studio/sigil/internal/securefile"
)

// TestRunRefusesDirectoriesOthersMayWrite covers the directory of client.yaml,
// which names the on_change programs the service runs as LocalSystem, and
// data_dir, whose certificates and keys the service writes to the outputs.
// Under C:\ProgramData any account may create a folder, owns it, and may give
// itself write access; one that Users may write to must stop the daemon
// before it reads anything from it.
func TestRunRefusesDirectoriesOthersMayWrite(t *testing.T) {
	for _, tt := range []struct {
		name, prefix string
		dataDir      bool
	}{
		{name: "configuration", prefix: "configuration directory: "},
		{name: "data", prefix: "data directory: ", dataDir: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			etc, data := filepath.Join(t.TempDir(), "etc"), filepath.Join(t.TempDir(), "data")
			path := filepath.Join(etc, "client.yaml")
			raw := fmt.Sprintf("client:\n  name: web-1\n  server_url: https://127.0.0.1:1\n  data_dir: %q\n  ipc_socket: %q\n",
				data, testIPCSocket(t))
			if err := securefile.WriteFile(path, []byte(raw)); err != nil {
				t.Fatal(err)
			}
			if err := securefile.EnsurePrivateDirectory(data); err != nil {
				t.Fatal(err)
			}
			refused := etc
			if tt.dataDir {
				refused = data
			}
			letUsersWrite(t, refused)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err := Run(ctx, path, setupLogs(t))
			if err == nil || !strings.HasPrefix(err.Error(), tt.prefix+refused+" ") {
				t.Fatalf("Run error = %v, want one that starts with %q", err, tt.prefix+refused)
			}
		})
	}
}

// letUsersWrite gives dir the ACL a folder created in C:\ProgramData
// inherits, which lets Users add files and folders to it.
func letUsersWrite(t *testing.T, dir string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user.User.Sid.String() + ")" +
			"(A;OICIIO;FA;;;CO)(A;OICI;0x1200a9;;;BU)(A;CI;0x116;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}
