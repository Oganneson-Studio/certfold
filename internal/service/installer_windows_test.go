//go:build windows

package service

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"golang.org/x/sys/windows"
)

// TestUnpackClientsCreatesPrivateDataDir covers `sigils service install
// --with-clients` before the daemon has first run, with data_dir under a
// directory that lets Users read what is created in it, as a new folder under
// C:\ does: the data_dir it creates, and binaries/ in it, grant Users nothing,
// so that no local user can put a binary there for the install scripts to
// hand out.
func TestUnpackClientsCreatesPrivateDataDir(t *testing.T) {
	parent := t.TempDir()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	readable, err := windows.SecurityDescriptorFromString(
		"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;0x1301bf;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := readable.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(parent, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}

	dataDir := filepath.Join(parent, "sigils")
	fsys := fstest.MapFS{"sigilc-windows-amd64.exe": &fstest.MapFile{Data: []byte("x")}}
	if _, err := UnpackClients(fsys, dataDir, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{dataDir, filepath.Join(dataDir, "binaries")} {
		descriptor, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		sddl := descriptor.String()
		if strings.Contains(sddl, ";;;BU)") {
			t.Errorf("%s grants Users access: %s", dir, sddl)
		}
		if dir != dataDir {
			continue
		}
		control, _, err := descriptor.Control()
		if err != nil {
			t.Fatal(err)
		}
		if control&windows.SE_DACL_PROTECTED == 0 {
			t.Errorf("the DACL of data_dir is not protected: %s", sddl)
		}
	}
}
