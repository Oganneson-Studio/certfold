//go:build !windows

package output

import (
	"fmt"
	"os/user"
	"strconv"
	"syscall"
)

// applyOwnership sets owner and group on path when the fields are non-empty.
// On non-Windows systems this uses syscall.Lchown with uid/gid lookup.
func applyOwnership(path, owner, group string) error {
	if owner == "" && group == "" {
		return nil
	}

	uid := -1
	gid := -1

	if owner != "" {
		u, err := user.Lookup(owner)
		if err != nil {
			return fmt.Errorf("lookup user %q: %w", owner, err)
		}
		uid, err = strconv.Atoi(u.Uid)
		if err != nil {
			return fmt.Errorf("parse uid for %q: %w", owner, err)
		}
	}

	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			return fmt.Errorf("lookup group %q: %w", group, err)
		}
		var err2 error
		gid, err2 = strconv.Atoi(g.Gid)
		if err2 != nil {
			return fmt.Errorf("parse gid for %q: %w", group, err2)
		}
	}

	if err := syscall.Lchown(path, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}
	return nil
}
