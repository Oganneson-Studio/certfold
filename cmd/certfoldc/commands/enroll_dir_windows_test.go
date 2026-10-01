//go:build windows

package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/Oganneson-Studio/certfold/internal/config"
)

// TestEnsureEnrollmentConfigRefusesDirectoryOthersCanWrite stands for a
// C:\ProgramData\Certfold that did not exist before certfoldc was installed. Under
// C:\ProgramData any account may create a folder and owns what it creates, so
// a local user can create Certfold\ and put a client.yaml in it that names this
// host and the server URL, both easy to guess, with an on_change program of
// its choosing. certfoldc enroll adopts that file, keeps the program and saves
// the identity into it; the service then runs the program as LocalSystem. The
// folder's owner also keeps WRITE_DAC and can replace client.yaml at any time
// later. Enrollment must refuse a config directory that accounts other than
// SYSTEM and Administrators may write to, and say which directory it is.
func TestEnsureEnrollmentConfigRefusesDirectoryOthersCanWrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Certfold")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	// The ACL a folder created under C:\ProgramData inherits.
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
	path := filepath.Join(dir, "client.yaml")
	planted := "client:\n  name: web-1\n  server_url: https://certfold.example.com\n" +
		"certificates:\n  web:\n    outputs:\n      - path: C:\\certs\\web.pem\n        format: pem-fullchain\n" +
		"    on_change: ['C:\\Windows\\System32\\cmd.exe', '/c', 'echo planted']\n"
	if err := os.WriteFile(path, []byte(planted), 0o600); err != nil {
		t.Fatal(err)
	}
	// Otherwise the refusal below could be a parse error that names the path.
	if _, err := config.LoadClient(path); err != nil {
		t.Fatalf("the planted client.yaml must be a valid configuration: %v", err)
	}

	_, _, err = ensureEnrollmentConfig(path, "web-1", "https://certfold.example.com")
	if err == nil {
		t.Fatal("enrollment adopted a client.yaml in a directory that Users may write to")
	}
	if !strings.Contains(err.Error(), dir) {
		t.Fatalf("error = %v, want one that names %s", err, dir)
	}
}
