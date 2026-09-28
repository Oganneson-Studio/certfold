//go:build windows

package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/Oganneson-Studio/sigil/internal/config"
)

// TestReconcileReplacesInheritedReadableKey covers a key file that an earlier
// version wrote with the directory's ACL: its rewrite must leave one that only
// the allowed accounts can open.
func TestReconcileReplacesInheritedReadableKey(t *testing.T) {
	path := filepath.Join(outputDir(t), "key.pem")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if sddl := fileSecurity(t, path).String(); !strings.Contains(sddl, ";;;BU)") {
		t.Fatalf("the old key should inherit Users read access: %s", sddl)
	}

	if !mustReconcile(t, makeBundle(t), config.OutputSpec{Format: "pem-key", Path: path}) {
		t.Fatal("the old key was not rewritten")
	}
	checkMode(t, path, 0o600)
}

// TestReconcileRestoresOwner covers an output whose owner was changed after
// it was written, for a format that createTemp gives a private DACL and one
// that inherits the directory's. The owner is the current user, then
// Administrators; one of them differs from the token's default owner, so
// applyOwnership has to set it.
func TestReconcileRestoresOwner(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("making Administrators the owner needs an elevated token")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	b := makeBundle(t)
	dir := outputDir(t)
	owners := []*windows.SID{user.User.Sid, admins}
	for i, owner := range owners {
		other := owners[1-i]
		for _, format := range []string{"pem-key", "pem-cert"} {
			t.Run(format+"/"+owner.String(), func(t *testing.T) {
				spec := config.OutputSpec{Format: format, Path: filepath.Join(dir, format+"-"+owner.String()), Owner: owner.String()}
				if !mustReconcile(t, b, spec) {
					t.Fatal("a missing output reported no change")
				}
				checkOwner(t, spec.Path, owner)
				before := fileState(t, spec.Path)
				if mustReconcile(t, b, spec) {
					t.Fatal("an output with the configured owner was rewritten")
				}
				checkUntouched(t, spec.Path, before)

				if err := windows.SetNamedSecurityInfo(spec.Path, windows.SE_FILE_OBJECT,
					windows.OWNER_SECURITY_INFORMATION, other, nil, nil, nil); err != nil {
					t.Fatal(err)
				}
				if !mustReconcile(t, b, spec) {
					t.Fatal("an output with another owner reported no change")
				}
				checkOwner(t, spec.Path, owner)
			})
		}
	}
}

func checkOwner(t *testing.T, path string, want *windows.SID) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatal(err)
	}
	if !owner.Equals(want) {
		t.Errorf("owner of %s = %s, want %s", path, owner, want)
	}
}
