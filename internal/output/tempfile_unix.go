//go:build !windows

package output

import (
	"os"

	"github.com/Oganneson-Studio/sigil/internal/config"
)

// createTemp creates the temporary file for an output in dir. os.CreateTemp
// creates it with mode 0600, so it stays private until applyMode sets the
// output mode.
func createTemp(dir string, _ config.OutputSpec) (*os.File, error) {
	return os.CreateTemp(dir, ".sigil-tmp-*")
}

// applyMode gives the temporary file the output's permission bits.
func applyMode(tmp *os.File, spec config.OutputSpec) error {
	return tmp.Chmod(os.FileMode(outputMode(spec)))
}

// modeMatches reports whether info has the permission bits applyMode gives
// the output.
func modeMatches(info os.FileInfo, spec config.OutputSpec) bool {
	return info.Mode().Perm() == os.FileMode(outputMode(spec))
}

// repairMetadata gives the output at spec.Path, whose content matches and
// which os.Lstat described as info, the permission bits and ownership that
// stage gives a temporary file. It sets them in place, in the order stage
// does: chmod when modeMatches fails, then chown when ownershipMatches fails.
// It does not stat the file again, and never has the output staged again.
func repairMetadata(info os.FileInfo, spec config.OutputSpec) (restage bool, err error) {
	if !modeMatches(info, spec) {
		if err := os.Chmod(spec.Path, os.FileMode(outputMode(spec))); err != nil {
			return false, err
		}
	}
	if !ownershipMatches(spec.Path, info, spec.Owner, spec.Group) {
		return false, applyOwnership(spec.Path, spec.Owner, spec.Group)
	}
	return false, nil
}
