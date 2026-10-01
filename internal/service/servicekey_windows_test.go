//go:build windows

package service

import (
	"fmt"
	"regexp"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// TestProtectRegistryKey covers what `service install` does to the registry
// key of the service on Windows, on a key of its own under HKEY_CURRENT_USER:
// a protected DACL with full control for SYSTEM and Administrators alone,
// which takes nothing from the key above, as the service key would take read
// access for Users from Services.
func TestProtectRegistryKey(t *testing.T) {
	sub := fmt.Sprintf(`Software\CertfoldServiceKeyTest-%d`, time.Now().UnixNano())
	key, _, err := registry.CreateKey(registry.CURRENT_USER, sub, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	_ = key.Close()
	path := `CURRENT_USER\` + sub
	t.Cleanup(func() {
		// The owner may change the DACL whatever it says; a NULL DACL lets
		// the test delete the key.
		if err := windows.SetNamedSecurityInfo(path, windows.SE_REGISTRY_KEY,
			windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, nil, nil); err != nil {
			t.Errorf("reset the DACL of the test key: %v", err)
		}
		if err := registry.DeleteKey(registry.CURRENT_USER, sub); err != nil {
			t.Errorf("delete the test key: %v", err)
		}
	})

	if err := protectRegistryKey(path); err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_REGISTRY_KEY, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("the DACL is not protected: %s", descriptor)
	}
	aces := regexp.MustCompile(`\([^)]*\)`).FindAllString(descriptor.String(), -1)
	if want := []string{"(A;CI;KA;;;SY)", "(A;CI;KA;;;BA)"}; !slices.Equal(aces, want) {
		t.Errorf("DACL entries = %v, want %v", aces, want)
	}
}
