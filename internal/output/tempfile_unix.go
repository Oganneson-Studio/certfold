//go:build !windows

package output

import (
	"fmt"
	"os"

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
	return applyOwnership(tmp.Name(), spec.Owner, spec.Group)
}

// modeMatches reports whether info has the permission bits applyMetadata
// gives the output.
func modeMatches(info os.FileInfo, spec config.OutputSpec) bool {
	return info.Mode().Perm() == os.FileMode(outputMode(spec))
}

// repairMetadata gives the output at spec.Path, whose content matches and
// which os.Lstat described as info, the permission bits and ownership that
// applyMetadata gives a temporary file. It sets them in place, in the same
// order: chmod when modeMatches fails, then chown when ownershipMatches fails.
// It does not stat the file again.
func repairMetadata(info os.FileInfo, spec config.OutputSpec) error {
	if !modeMatches(info, spec) {
		if err := os.Chmod(spec.Path, os.FileMode(outputMode(spec))); err != nil {
			return err
		}
	}
	if !ownershipMatches(info, spec.Owner, spec.Group) {
		return applyOwnership(spec.Path, spec.Owner, spec.Group)
	}
	return nil
}
