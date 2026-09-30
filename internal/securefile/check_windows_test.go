//go:build windows

package securefile

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestCheckSecurity covers the owner and the entries of a directory's DACL,
// for both checks. Only a trustee may own the directory; CheckDirectory
// refuses an account that may write to it or change who may, and
// CheckPrivateDirectory any access by one, including access its files
// inherit, since SQLite creates -wal and -shm in data_dir again and again.
func TestCheckSecurity(t *testing.T) {
	trusted, _, err := trustees()
	if err != nil {
		t.Fatal(err)
	}
	const path = `C:\ProgramData\Sigil`
	const trustedACEs = "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	// Windows translates the names of these accounts.
	users, everyone := accountOf(t, "S-1-5-32-545"), accountOf(t, "S-1-1-0")
	authenticated := accountOf(t, "S-1-5-11")
	for _, tt := range []struct {
		name string
		sddl string
		// Substrings of the error of CheckDirectory and of
		// CheckPrivateDirectory; empty when the check passes.
		write, private []string
	}{
		{
			name: "private",
			sddl: "O:BAD:P" + trustedACEs,
		},
		{
			name:    "owned by Users",
			sddl:    "O:BUD:P" + trustedACEs,
			write:   []string{path, "is owned by " + users, `icacls "` + path + `" /setowner *S-1-5-32-544`},
			private: []string{path, "is owned by " + users},
		},
		{
			// The ACL a folder that an administrator creates in
			// C:\ProgramData inherits: Users may add files and folders to it.
			name: "created in ProgramData",
			sddl: "O:BAD:AI(A;OICIIOID;GA;;;CO)(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)" +
				"(A;OICIID;0x1200a9;;;BU)(A;CIID;0x116;;;BU)",
			write: []string{path, users + " write to it or change its permissions",
				`icacls "` + path + `" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F`,
				"/remove:g *S-1-5-32-545"},
			private: []string{path, users + " access it"},
		},
		{
			name:    "readable by Users",
			sddl:    "O:BAD:P" + trustedACEs + "(A;OICI;FR;;;BU)",
			private: []string{path, users + " access it"},
		},
		{
			// Grants nothing on the directory itself, but the -wal and
			// -shm that SQLite creates in it would inherit it.
			name:    "files readable by Users",
			sddl:    "O:BAD:P" + trustedACEs + "(A;OIIO;FR;;;BU)",
			private: []string{users + " access it"},
		},
		{
			name:    "DACL changeable by Everyone",
			sddl:    "O:BAD:P" + trustedACEs + "(A;;WD;;;WD)",
			write:   []string{everyone + " write to it", "/remove:g *S-1-1-0"},
			private: []string{everyone + " access it"},
		},
		{
			name:    "deletable by Authenticated Users",
			sddl:    "O:BAD:P" + trustedACEs + "(A;;SD;;;AU)",
			write:   []string{authenticated + " write to it"},
			private: []string{authenticated + " access it"},
		},
		{
			// 0x40 is FILE_DELETE_CHILD.
			name:    "children deletable by Users",
			sddl:    "O:BAD:P" + trustedACEs + "(A;;0x40;;;BU)",
			write:   []string{users + " write to it"},
			private: []string{users + " access it"},
		},
		{
			name:    "every account listed once",
			sddl:    "O:BAD:P" + trustedACEs + "(A;;FA;;;BU)(A;OICI;FA;;;BU)(A;;FA;;;WD)",
			write:   []string{users + ", " + everyone + " write", "/remove:g *S-1-5-32-545 *S-1-1-0"},
			private: []string{users + ", " + everyone + " access"},
		},
		{
			// It stands for the account that creates a file, which no
			// one but a trustee may do.
			name: "creator owner",
			sddl: "O:BAD:P" + trustedACEs + "(A;OICIIO;GA;;;CO)",
		},
		{
			name: "access denied to Users",
			sddl: "O:BAD:P(D;OICI;FA;;;BU)" + trustedACEs,
		},
		{
			name:    "null DACL",
			sddl:    "O:BAD:NO_ACCESS_CONTROL",
			write:   []string{everyone + " write to it"},
			private: []string{everyone + " access it"},
		},
		{
			// A conditional entry has its SID elsewhere.
			name:    "conditional entry",
			sddl:    "O:BAD:P" + trustedACEs + "(XA;;FA;;;WD;(Member_of {SID(BA)}))",
			write:   []string{path, "type 9"},
			private: []string{path, "type 9"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			descriptor, err := windows.SecurityDescriptorFromString(tt.sddl)
			if err != nil {
				t.Fatal(err)
			}
			for _, check := range []struct {
				name      string
				forbidden windows.ACCESS_MASK
				what      string
				want      []string
			}{
				{"CheckDirectory", writeAccess, "write to it or change its permissions", tt.write},
				{"CheckPrivateDirectory", ^windows.ACCESS_MASK(0), "access it", tt.private},
			} {
				err := checkSecurity(path, descriptor, trusted, check.forbidden, check.what)
				if len(check.want) == 0 {
					if err != nil {
						t.Errorf("%s: %v, want it to pass", check.name, err)
					}
					continue
				}
				if err == nil {
					t.Errorf("%s passed, want an error", check.name)
					continue
				}
				for _, want := range check.want {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("%s: %v\nwant it to contain %q", check.name, err, want)
					}
				}
			}
		})
	}
}

// TestCheckDirectoryReadsDirectory covers the checks on directories on disk:
// one that EnsurePrivateDirectory created, one whose files Users may read, and
// one that does not exist, which only CheckDirectory lets pass.
func TestCheckDirectoryReadsDirectory(t *testing.T) {
	private := filepath.Join(t.TempDir(), "private")
	if err := EnsurePrivateDirectory(private); err != nil {
		t.Fatal(err)
	}
	if err := CheckDirectory(private); err != nil {
		t.Errorf("CheckDirectory of a private directory: %v", err)
	}
	if err := CheckPrivateDirectory(private); err != nil {
		t.Errorf("CheckPrivateDirectory of a private directory: %v", err)
	}

	readable := filepath.Join(t.TempDir(), "readable")
	if err := EnsurePrivateDirectory(readable); err != nil {
		t.Fatal(err)
	}
	trusted, _, err := trustees()
	if err != nil {
		t.Fatal(err)
	}
	sddl := "D:P(A;OICI;FR;;;BU)"
	for _, trustee := range trusted {
		sddl += "(A;OICI;FA;;;" + trustee.String() + ")"
	}
	setDACL(t, readable, sddl)
	if err := CheckDirectory(readable); err != nil {
		t.Errorf("CheckDirectory of a directory Users may read: %v", err)
	}
	if err := CheckPrivateDirectory(readable); err == nil || !strings.Contains(err.Error(), readable) {
		t.Errorf("CheckPrivateDirectory of a directory Users may read: %v, want an error that names it", err)
	}

	missing := filepath.Join(t.TempDir(), "missing")
	if err := CheckDirectory(missing); err != nil {
		t.Errorf("CheckDirectory of a missing directory: %v", err)
	}
	if err := CheckPrivateDirectory(missing); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("CheckPrivateDirectory of a missing directory: %v, want os.ErrNotExist", err)
	}
}

// TestCreatedWithTrustedOwnerWhateverTheDefaultOwner covers a process whose
// token makes the user's own account the owner of what it creates, as MSYS
// does for the programs Git Bash starts. What securefile creates must still
// have an owner that the checks trust, which in an elevated process the user
// is not: the directories of EnsurePrivateDirectory and WriteFile, and the
// files of CreateTemp.
func TestCreatedWithTrustedOwnerWhateverTheDefaultOwner(t *testing.T) {
	makeUserDefaultOwner(t)

	dir := filepath.Join(t.TempDir(), "private")
	if err := EnsurePrivateDirectory(dir); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivateDirectory(dir); err != nil {
		t.Errorf("a directory EnsurePrivateDirectory created: %v", err)
	}
	path := filepath.Join(t.TempDir(), "etc", "client.yaml")
	if err := WriteFile(path, []byte("private")); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivateDirectory(filepath.Dir(path)); err != nil {
		t.Errorf("a directory WriteFile created: %v", err)
	}

	tmp, err := CreateTemp(dir, ".sigil-private-*")
	if err != nil {
		t.Fatal(err)
	}
	defer tmp.Close()
	descriptor, err := windows.GetSecurityInfo(windows.Handle(tmp.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatal(err)
	}
	trusted, _, err := trustees()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(trusted, owner.Equals) {
		t.Errorf("a file CreateTemp created is owned by %s, which the checks do not trust", accountName(owner))
	}
}

// makeUserDefaultOwner makes the user the default owner of the process token
// until the test ends.
func makeUserDefaultOwner(t *testing.T) {
	t.Helper()
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT, &token); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = token.Close() })
	var size uint32
	_ = windows.GetTokenInformation(token, windows.TokenOwner, nil, 0, &size)
	previous := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenOwner, &previous[0], size, &size); err != nil {
		t.Fatal(err)
	}
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	owner := struct{ Owner *windows.SID }{user.User.Sid}
	if err := windows.SetTokenInformation(token, windows.TokenOwner, (*byte)(unsafe.Pointer(&owner)), uint32(unsafe.Sizeof(owner))); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := windows.SetTokenInformation(token, windows.TokenOwner, &previous[0], uint32(len(previous))); err != nil {
			t.Errorf("restore the default owner: %v", err)
		}
	})
}

func setDACL(t *testing.T, path, sddl string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

// accountOf returns the name that the errors give the account with the SID
// sid.
func accountOf(t *testing.T, sid string) string {
	t.Helper()
	s, err := windows.StringToSid(sid)
	if err != nil {
		t.Fatal(err)
	}
	return accountName(s)
}
