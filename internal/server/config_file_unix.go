//go:build !windows

package server

import (
	"os"
	"syscall"
)

// keepMetadata gives tmp the owner and mode of the file info describes.
func keepMetadata(tmp *os.File, info os.FileInfo) error {
	stat := info.Sys().(*syscall.Stat_t)
	if err := tmp.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
		return err
	}
	return tmp.Chmod(info.Mode().Perm())
}
