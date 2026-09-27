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
