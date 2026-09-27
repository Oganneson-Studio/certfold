//go:build windows

package securefile

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWriteFileUsesProtectedWindowsDACL(t *testing.T) {
	path := t.TempDir() + `\client.yaml`
	if err := WriteFile(path, []byte("private")); err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatal(err)
	}
	sddl := descriptor.String()
	if !strings.HasPrefix(sddl, "D:P") {
		t.Fatalf("DACL is not protected: %s", sddl)
	}
	if strings.Contains(sddl, ";;;WD)") || strings.Contains(sddl, ";;;BU)") {
		t.Fatalf("DACL grants access to broad principals: %s", sddl)
	}
}

// TestCreateTempIsPrivateBeforeWrite covers the moment between creating a
// temporary file and writing to it. Windows checks access only when a handle
// is opened, so an account that opened the empty file then could read
// everything written to it later: the file must be private as soon as it
// exists, even in a directory whose files Users may read.
func TestCreateTempIsPrivateBeforeWrite(t *testing.T) {
	tmp, err := CreateTemp(usersReadableDir(t), ".sigil-private-*")
	if err != nil {
		t.Fatal(err)
	}
	defer tmp.Close()
	descriptor, err := windows.GetSecurityInfo(
		windows.Handle(tmp.Fd()),
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatal(err)
	}
	checkPrivate(t, descriptor)
}

// checkPrivate fails unless descriptor has a protected DACL that grants
// nothing to Users, Authenticated Users or Everyone.
func checkPrivate(t *testing.T, descriptor *windows.SECURITY_DESCRIPTOR) {
	t.Helper()
	sddl := descriptor.String()
	if !strings.HasPrefix(sddl, "D:P") {
		t.Fatalf("DACL is not protected: %s", sddl)
	}
	for _, broad := range []string{"BU", "AU", "WD"} {
		if strings.Contains(sddl, ";;;"+broad+")") {
			t.Fatalf("DACL grants %s: %s", broad, sddl)
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
