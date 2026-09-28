//go:build windows

package output

import (
	"os"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/securefile"
)

// createTemp creates the temporary file for an output in dir. os.Chmod(0600)
// cannot restrict access on Windows, so a format that carries the private key
// is created by securefile.CreateTemp, whose protected DACL grants only
// SYSTEM, Administrators, the current user and, for reading, spec.Owner: the
// owner consumes the key and sigilc does every write. Other formats inherit
// the directory's ACL.
func createTemp(dir string, spec config.OutputSpec) (*os.File, error) {
	if !carriesKey(spec.Format) {
		return os.CreateTemp(dir, ".sigil-tmp-*")
	}
	if spec.Owner == "" {
		return securefile.CreateTemp(dir, ".sigil-tmp-*")
	}
	owner, err := lookupAccount(spec.Owner)
	if err != nil {
		return nil, err
	}
	return securefile.CreateTemp(dir, ".sigil-tmp-*", owner)
}

// applyMode does nothing on Windows. Chmod only sets or clears the read-only
// attribute there, and a read-only output cannot be replaced by the next
// rewrite; createTemp sets the access controls instead.
func applyMode(*os.File, config.OutputSpec) error { return nil }

// repairMetadata reports whether the output at spec.Path, whose content
// matches and which os.Lstat described as info, must be staged again: when
// ownershipMatches fails. The owner is not set in place, since that would
// leave the DACL createTemp gave a private-key output, which grants read
// access to the owner configured when it was written. The mode is not
// compared, since Windows does not apply it, and neither is the DACL.
func repairMetadata(info os.FileInfo, spec config.OutputSpec) (restage bool, err error) {
	return !ownershipMatches(spec.Path, info, spec.Owner, spec.Group), nil
}
