//go:build windows

package output

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

// applyOwnership sets the owner SID on path via SetNamedSecurityInfo.
// group is ignored on Windows; only owner is applied. No-op when owner is empty.
func applyOwnership(path, owner, group string) error {
	if owner == "" {
		return nil
	}

	sid, err := lookupAccount(owner)
	if err != nil {
		return err
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

// lookupAccount resolves owner, which may be a SID string (S-1-5-...) or an
// account name. StringToSid also accepts SDDL aliases such as "BU" (Users) or
// "WD" (Everyone), so only strings starting with "S-" are parsed as SIDs.
func lookupAccount(owner string) (*windows.SID, error) {
	if strings.HasPrefix(owner, "S-") {
		sid, err := windows.StringToSid(owner)
		if err != nil {
			return nil, fmt.Errorf("parse SID %q: %w", owner, err)
		}
		return sid, nil
	}
	sid, _, _, err := windows.LookupSID("", owner)
	if err != nil {
		return nil, fmt.Errorf("lookup account %q: %w", owner, err)
	}
	return sid, nil
}
