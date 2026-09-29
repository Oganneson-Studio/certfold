//go:build windows

package server

import "os"

// keepMetadata leaves tmp as securefile.CreateTemp created it. Windows has no
// mode, and giving a file an owner other than the daemon's account takes a
// privilege that LocalSystem does not enable by default.
func keepMetadata(*os.File, os.FileInfo) error { return nil }
