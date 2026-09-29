//go:build windows

package output

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

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
