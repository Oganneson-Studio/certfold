//go:build !windows

package service

import (
	"log/slog"
	"os"
)

// daemonLog returns the service log of a daemon and a function that closes
// it. It is stderr, which systemd passes to journald and launchd writes to a
// file.
func daemonLog(Role, bool) (slog.Handler, func()) {
	return slog.NewTextHandler(os.Stderr, nil), func() {}
}
