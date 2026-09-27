//go:build windows

package output

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// checkMode checks the DACL that stands in for Unix permission bits on
// Windows. An owner-only mode requires a protected DACL that grants nothing to
// Users, Authenticated Users or Everyone; any other mode keeps the inherited
// DACL.
func checkMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	descriptor := fileSecurity(t, path)
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatal(err)
	}
	protected := control&windows.SE_DACL_PROTECTED != 0
	sddl := descriptor.String()
	if want&0o077 != 0 {
		if protected {
			t.Errorf("public output has a protected DACL: %s", sddl)
		}
		return
	}
	if !protected {
		t.Errorf("DACL is not protected: %s", sddl)
	}
	for _, broad := range []string{"BU", "AU", "WD"} {
		if strings.Contains(sddl, ";;;"+broad+")") {
			t.Errorf("DACL grants %s: %s", broad, sddl)
		}
	}
}

func fileSecurity(t *testing.T, path string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}

// outputDir returns a directory whose inheritable ACL lets Users read the
// files created in it, as a new folder under C:\ does.
func outputDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FR;;;BU)")
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
	return dir
}
