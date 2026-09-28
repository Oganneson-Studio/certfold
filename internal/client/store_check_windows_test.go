//go:build windows

package client

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// checkPrivate fails unless path has a protected DACL that grants nothing to
// Users, Authenticated Users or Everyone.
func checkPrivate(t *testing.T, path string) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatal(err)
	}
	sddl := descriptor.String()
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("DACL is not protected: %s", sddl)
	}
	for _, broad := range []string{"BU", "AU", "WD"} {
		if strings.Contains(sddl, ";;;"+broad+")") {
			t.Errorf("DACL grants %s: %s", broad, sddl)
		}
	}
}

// usersReadableDir returns a directory whose inheritable ACL lets Users read
// the files created in it, as a new folder under C:\ does.
func usersReadableDir(t *testing.T) string {
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
