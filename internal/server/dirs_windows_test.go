//go:build windows

package server

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestRunRefusesConfigurationDirectoryOthersMayWrite covers the directory of
// server.yaml, which names the programs certfolds runs as LocalSystem and where
// it keeps its keys. Under C:\ProgramData any account may create a folder,
// owns it, and may give itself write access; one that Users may write to must
// stop the daemon before it reads server.yaml: this one does not parse.
func TestRunRefusesConfigurationDirectoryOthersMayWrite(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "server.yaml")
	if err := os.WriteFile(path, []byte("server: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	letUsersWrite(t, dir)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := Run(ctx, path, setupLogs(t, io.Discard))
	if want := "configuration directory: " + dir + " "; err == nil || !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("Run error = %v, want one that starts with %q", err, want)
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
