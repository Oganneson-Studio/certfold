//go:build windows

package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/Oganneson-Studio/certfold/internal/config"
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

// TestReconcileReplacesOutputWithReadOnlyMode covers an explicit mode without
// the owner write bit. Chmod would mark the output read-only on Windows, and
// the next rewrite could not replace it.
func TestReconcileReplacesOutputWithReadOnlyMode(t *testing.T) {
	dir := outputDir(t)
	for _, format := range []string{"pem-key", "pem-cert"} {
		spec := config.OutputSpec{Format: format, Path: filepath.Join(dir, format), Mode: 0o440}
		// A new bundle each time, so the second reconcile replaces the output.
		for attempt := 1; attempt <= 2; attempt++ {
			if _, err := Reconcile(makeBundle(t), []config.OutputSpec{spec}); err != nil {
				t.Fatalf("%s reconcile %d: %v", format, attempt, err)
			}
		}
	}
}

// TestReconcileGivesKeyOutputToServiceAccount covers owner set to the account
// of a service that reads the key, as README tells Windows operators to do for
// IIS or nginx. The account gets read access to the key and does not become
// its owner: making another account the owner needs SeRestorePrivilege, which
// LocalSystem holds disabled, so every round would fail, and an owner may
// change the DACL. An output that matches is left alone with owner set.
func TestReconcileGivesKeyOutputToServiceAccount(t *testing.T) {
	networkService, err := windows.CreateWellKnownSid(windows.WinNetworkServiceSid)
	if err != nil {
		t.Fatal(err)
	}
	b := makeBundle(t)
	spec := config.OutputSpec{
		Format: "pem-key",
		Path:   filepath.Join(outputDir(t), "key.pem"),
		Owner:  `NT AUTHORITY\NETWORK SERVICE`,
	}
	if !mustReconcile(t, b, spec) {
		t.Fatal("a missing output reported no change")
	}
	checkMode(t, spec.Path, 0o600)
	if sddl := fileSecurity(t, spec.Path).String(); !strings.Contains(sddl, "(A;;FR;;;NS)") {
		t.Errorf("DACL does not grant NETWORK SERVICE read access: %s", sddl)
	}
	descriptor, err := windows.GetNamedSecurityInfo(spec.Path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if owner, _, err := descriptor.Owner(); err != nil || owner.Equals(networkService) {
		t.Errorf("owner of %s = %v, %v; want it left to the account of certfoldc", spec.Path, owner, err)
	}

	before := fileState(t, spec.Path)
	if mustReconcile(t, b, spec) {
		t.Fatal("an output that matches reported a change")
	}
	checkUntouched(t, spec.Path, before)
}
