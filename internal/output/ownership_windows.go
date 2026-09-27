//go:build windows

package output

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// applyOwnership sets the owner SID on path via SetNamedSecurityInfo.
// group is ignored on Windows; only owner is applied. No-op when owner is empty.
func applyOwnership(path, owner, group string) error {
	if owner == "" {
		return nil
	}

	// owner may be a SID string (S-1-5-...) or an account name.
	sid, err := windows.StringToSid(owner)
	if err != nil {
		// Fall back to account name lookup.
		sid, _, _, err = windows.LookupSID("", owner)
		if err != nil {
			return fmt.Errorf("lookup account %q: %w", owner, err)
		}
	}

	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
		sid, nil, nil, nil,
	); err != nil {
		return fmt.Errorf("SetNamedSecurityInfo %s: %w", path, err)
	}
	return nil
}
