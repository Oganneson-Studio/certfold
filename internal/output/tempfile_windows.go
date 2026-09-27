//go:build windows

package output

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Oganneson-Studio/sigil/internal/config"
)

// createTemp creates the temporary file for an output in dir. os.Chmod(0600)
// cannot restrict access on Windows, so a format that carries the private key
// is created with a protected DACL that grants only SYSTEM, Administrators,
// the current user and spec.Owner. Setting the DACL at creation leaves no
// moment in which another account could open the file and keep the handle.
// Other formats inherit the directory's ACL.
func createTemp(dir string, spec config.OutputSpec) (*os.File, error) {
	if !carriesKey(spec.Format) {
		return os.CreateTemp(dir, ".sigil-tmp-*")
	}
	descriptor, err := privateDescriptor(spec.Owner)
	if err != nil {
		return nil, err
	}
	attributes := windows.SecurityAttributes{SecurityDescriptor: descriptor}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	for range 100 {
		name := filepath.Join(dir, ".sigil-tmp-"+strconv.FormatUint(rand.Uint64(), 36))
		path, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return nil, err
		}
		handle, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0,
			&attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err == windows.ERROR_FILE_EXISTS {
			continue
		}
		if err != nil {
			return nil, &os.PathError{Op: "createtemp", Path: name, Err: err}
		}
		return os.NewFile(uintptr(handle), name), nil
	}
	return nil, fmt.Errorf("no unused temporary file name in %s", dir)
}

// privateDescriptor builds a protected DACL with full access for SYSTEM,
// Administrators, the current user and, when set, owner.
func privateDescriptor(owner string) (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("get current user: %w", err)
	}
	sddl := "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + user.User.Sid.String() + ")"
	if owner != "" {
		sid, err := lookupAccount(owner)
		if err != nil {
			return nil, err
		}
		sddl += "(A;;FA;;;" + sid.String() + ")"
	}
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("build security descriptor: %w", err)
	}
	return descriptor, nil
}
