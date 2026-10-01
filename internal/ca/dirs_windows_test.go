//go:build windows

package ca

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/Oganneson-Studio/certfold/internal/securefile"
)

// TestBootstrapRefusesCADirectoryOthersMayWrite covers a ca\ that an account
// certfolds does not trust could put a key of its own in, say one created while
// data_dir was not private: Bootstrap must refuse it before it tightens it,
// and write nothing to it.
func TestBootstrapRefusesCADirectoryOthersMayWrite(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	dir := filepath.Join(dataDir, caSubDir)
	if err := securefile.EnsurePrivateDirectory(dir); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	// The ACL a folder created in C:\ProgramData inherits: Users may add
	// files and folders to it.
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

	if _, err := Bootstrap(dataDir); err == nil || !strings.Contains(err.Error(), dir+" ") {
		t.Fatalf("Bootstrap error = %v, want one that names %s", err, dir)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("Bootstrap left %v (%v) in the directory it refused", entries, err)
	}
	after, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(after.String(), ";;;BU)") {
		t.Fatalf("Bootstrap changed the DACL of the directory it refused: %s", after)
	}
}
