//go:build !windows

package output

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// applyOwnership gives f owner and group, each when set, with fchown. Its
// error does not name f, which may be a temporary file with a random name;
// every caller names the output.
func applyOwnership(f *os.File, owner, group string) error {
	if owner == "" && group == "" {
		return nil
	}

	uid, gid, err := lookupOwnership(owner, group)
	if err != nil {
		return err
	}

	if err := f.Chown(uid, gid); err != nil {
		return fmt.Errorf("chown: %w", withoutTempName(err))
	}
	return nil
}

// ownershipMatches reports whether info has the uid of owner and the gid of
// group, each checked only when set. A name that does not resolve does not
// match; applyOwnership then reports the error.
func ownershipMatches(info os.FileInfo, owner, group string) bool {
	if owner == "" && group == "" {
		return true
	}
	uid, gid, err := lookupOwnership(owner, group)
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (uid == -1 || int(stat.Uid) == uid) && (gid == -1 || int(stat.Gid) == gid)
}

// lookupOwnership resolves owner and group to the uid and gid that Chown
// takes: -1 for an empty name.
func lookupOwnership(owner, group string) (int, int, error) {
	uid := -1
	gid := -1

	if owner != "" {
		u, err := user.Lookup(owner)
		if err != nil {
			return 0, 0, fmt.Errorf("lookup user %q: %w", owner, err)
		}
		uid, err = strconv.Atoi(u.Uid)
		if err != nil {
			return 0, 0, fmt.Errorf("parse uid for %q: %w", owner, err)
		}
	}

	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			return 0, 0, fmt.Errorf("lookup group %q: %w", group, err)
		}
		var err2 error
		gid, err2 = strconv.Atoi(g.Gid)
		if err2 != nil {
			return 0, 0, fmt.Errorf("parse gid for %q: %w", group, err2)
		}
	}
	return uid, gid, nil
}
