//go:build windows

package store

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func makeSQLiteDirectoryBroad(t *testing.T, path string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString("D:(A;OICI;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		t.Fatal(err)
	}
}

func assertPrivateSQLiteFile(t *testing.T, path string) {
	t.Helper()
	sddl := fileSecurityDescriptor(t, path)
	if !strings.HasPrefix(sddl, "D:P") {
		t.Fatalf("DACL for %s is not protected: %s", path, sddl)
	}
	assertNoBroadAccess(t, path, sddl)
}

func assertPrivateSQLiteDirectory(t *testing.T, path string) {
	t.Helper()
	sddl := fileSecurityDescriptor(t, path)
	if !strings.HasPrefix(sddl, "D:P") {
		t.Fatalf("DACL for %s is not protected: %s", path, sddl)
	}
	if !strings.Contains(sddl, "OICI") {
		t.Fatalf("DACL for %s does not propagate to child files: %s", path, sddl)
	}
	assertNoBroadAccess(t, path, sddl)
}

func fileSecurityDescriptor(t *testing.T, path string) string {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatal(err)
	}
	return descriptor.String()
}

func assertNoBroadAccess(t *testing.T, path, sddl string) {
	t.Helper()
	for _, principal := range []string{"WD", "BU", "AU"} {
		if strings.Contains(sddl, ";;;"+principal+")") {
			t.Fatalf("DACL for %s grants broad access: %s", path, sddl)
		}
	}
}
