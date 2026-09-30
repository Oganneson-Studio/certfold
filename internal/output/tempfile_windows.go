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
// the directory's ACL, and ignore spec.Owner.
//
// spec.Owner does not become the owner of the file. Setting another account as
// owner needs SeRestorePrivilege, which LocalSystem and an elevated
// administrator hold disabled, and an owner may change the DACL, which would
// give the account that consumes the key more than read access.
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

// applyMetadata does nothing on Windows. Chmod only sets or clears the
// read-only attribute there, and a read-only output cannot be replaced by the
// next rewrite; createTemp sets the access controls instead.
func applyMetadata(*os.File, config.OutputSpec) error { return nil }

// openOutput opens the output at path for reading, and returns it with what
// os.Lstat found for it, when that is a regular file: a symbolic link is not
// followed. Nothing is set through the path after that on Windows, where
// repairMetadata does nothing.
func openOutput(path string) (*os.File, os.FileInfo, bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, nil, false
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, false
	}
	return f, info, true
}

// repairMetadata does nothing on Windows: Reconcile compares only the content
// of an output there. The mode is not applied, the owner is not set, and the
// DACL that createTemp gave the output is not compared.
func repairMetadata(*os.File, os.FileInfo, config.OutputSpec) error { return nil }
