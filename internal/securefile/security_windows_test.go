//go:build windows

package securefile

import (
	"os"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestWriteFileUsesProtectedWindowsDACL writes into a directory whose files
// Users may read: a new file, and one that an earlier version wrote with the
// directory's ACL. The temporary file keeps the DACL that CreateTemp gave it
// when it replaces path; nothing tightens the result afterwards.
func TestWriteFileUsesProtectedWindowsDACL(t *testing.T) {
	dir := usersReadableDir(t)
	old := dir + `\client.yaml`
	if err := os.WriteFile(old, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if sddl := fileSecurity(t, old).String(); !strings.Contains(sddl, ";;;BU)") {
		t.Fatalf("the old file should inherit Users read access: %s", sddl)
	}
	for _, path := range []string{dir + `\new.yaml`, old} {
		if err := WriteFile(path, []byte("private")); err != nil {
			t.Fatal(err)
		}
		checkPrivate(t, fileSecurity(t, path))
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

// TestCreateTempGrantsUserOnlyWithoutAdministrators covers the account of
// the process in the DACL. An elevated administrator, like LocalSystem,
// reaches the file through Administrators: an entry for their own account
// would let their programs that run without elevation write it too. A user
// without Administrators enabled needs the entry. The test asserts the case
// of the shell it runs in.
func TestCreateTempGrantsUserOnlyWithoutAdministrators(t *testing.T) {
	tmp, err := CreateTemp(t.TempDir(), ".sigil-private-*")
	if err != nil {
		t.Fatal(err)
	}
	defer tmp.Close()
	descriptor, err := windows.GetSecurityInfo(windows.Handle(tmp.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	elevated, err := windows.Token(0).IsMember(admins)
	if err != nil {
		t.Fatal(err)
	}
	granted := false
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if (*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(user.User.Sid) {
			granted = true
		}
	}
	if granted == elevated {
		t.Fatalf("Administrators enabled: %t, DACL grants the current user: %t; want exactly one of them: %s", elevated, granted, descriptor)
	}
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

func fileSecurity(t *testing.T, path string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
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
