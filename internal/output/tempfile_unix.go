//go:build !windows

package output

import (
	"fmt"
	"os"
	"syscall"

	"github.com/Oganneson-Studio/sigil/internal/config"
)

// createTemp creates the temporary file for an output in dir. os.CreateTemp
// creates it with mode 0600, so it stays private until applyMetadata sets the
// output mode.
func createTemp(dir string, _ config.OutputSpec) (*os.File, error) {
	return os.CreateTemp(dir, ".sigil-tmp-*")
}

// applyMetadata gives the temporary file the output's permission bits, then
// its owner and group.
func applyMetadata(tmp *os.File, spec config.OutputSpec) error {
	if err := tmp.Chmod(os.FileMode(outputMode(spec))); err != nil {
		return fmt.Errorf("chmod temp: %w", withoutTempName(err))
	}
	return applyOwnership(tmp, spec.Owner, spec.Group)
}

// openOutput opens the output at path for reading, and returns it with what
// fstat found for it, when that is a regular file. O_NOFOLLOW fails on a
// symbolic link, and O_NONBLOCK returns at once from opening a FIFO, which
// fstat then tells apart: waiting for a writer would hold pullMu and stop
// every round of sigilc.
func openOutput(path string) (*os.File, os.FileInfo, bool) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, false
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, false
	}
	return f, info, true
}

// modeMatches reports whether info has the permission bits applyMetadata
// gives the output.
func modeMatches(info os.FileInfo, spec config.OutputSpec) bool {
	return info.Mode().Perm() == os.FileMode(outputMode(spec))
}

// repairMetadata gives the output f, whose content matches and which fstat
// described as info, the permission bits and ownership that applyMetadata
// gives a temporary file. It sets them on f, in the same order: fchmod when
// modeMatches fails, then fchown when ownershipMatches fails. It does not
// stat the file again.
func repairMetadata(f *os.File, info os.FileInfo, spec config.OutputSpec) error {
	if !modeMatches(info, spec) {
		if err := f.Chmod(os.FileMode(outputMode(spec))); err != nil {
			return err
		}
	}
	if !ownershipMatches(info, spec.Owner, spec.Group) {
		return applyOwnership(f, spec.Owner, spec.Group)
	}
	return nil
}
