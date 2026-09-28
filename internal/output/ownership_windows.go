//go:build windows

package output

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// applyOwnership sets the owner SID on path via SetNamedSecurityInfo.
// group is ignored on Windows; only owner is applied. No-op when owner is empty.
// Its error does not name path, a temporary file with a random name; the
// caller names the output.
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
		return fmt.Errorf("SetNamedSecurityInfo: %w", err)
	}
	return nil
}

// ownershipMatches reports whether the owner SID of path is that of owner,
// when owner is set; group is ignored, as applyOwnership ignores it. An owner
// that does not resolve does not match; applyOwnership then reports the error.
func ownershipMatches(path string, _ os.FileInfo, owner, _ string) bool {
	if owner == "" {
		return true
	}
	want, err := lookupAccount(owner)
	if err != nil {
		return false
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	got, _, err := descriptor.Owner()
	return err == nil && got.Equals(want)
}

// lookupAccount resolves owner, which may be a SID string (S-1-5-...) or an
// account name. StringToSid also accepts SDDL aliases such as "BU" (Users) or
// "WD" (Everyone), so only strings starting with "S-" in any case are tried as
// SIDs; one that does not parse is looked up as an account name.
func lookupAccount(owner string) (*windows.SID, error) {
	if len(owner) > 2 && strings.EqualFold(owner[:2], "S-") {
		if sid, err := windows.StringToSid(owner); err == nil {
			return sid, nil
		}
	}
	sid, _, _, err := windows.LookupSID("", owner)
	if err != nil {
		return nil, fmt.Errorf("lookup account %q: %w", owner, err)
	}
	return sid, nil
}
