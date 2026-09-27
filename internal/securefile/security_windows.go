//go:build windows

package securefile

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CreateTemp creates a new file in dir, named by replacing the last "*" in
// pattern with a random string as os.CreateTemp does, and opens it for reading
// and writing. The file is created with a protected DACL that grants full
// access to SYSTEM, Administrators and the current user and read access to
// readers, and inherits nothing from dir. Windows checks access only when a
// handle is opened, so tightening the DACL after creation would let another
// account open the empty file first and read what is written to it later.
func CreateTemp(dir, pattern string, readers ...*windows.SID) (*os.File, error) {
	descriptor, err := privateDescriptor(false, readers...)
	if err != nil {
		return nil, err
	}
	attributes := windows.SecurityAttributes{SecurityDescriptor: descriptor}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	prefix, suffix := pattern, ""
	if i := strings.LastIndexByte(pattern, '*'); i >= 0 {
		prefix, suffix = pattern[:i], pattern[i+1:]
	}
	for range 100 {
		name := filepath.Join(dir, prefix+strconv.FormatUint(rand.Uint64(), 36)+suffix)
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

func secureDirectory(path string) error {
	return applyProtectedDACL(path, true)
}

func secureFile(path string) error {
	return applyProtectedDACL(path, false)
}

func applyProtectedDACL(path string, inherit bool) error {
	descriptor, err := privateDescriptor(inherit)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read security descriptor DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf("set DACL: %w", err)
	}
	return nil
}

// privateDescriptor builds a protected DACL with full access for SYSTEM,
// Administrators and the current user and read access for readers. For a
// directory, inherit passes every entry on to the files and directories
// created in it.
func privateDescriptor(inherit bool, readers ...*windows.SID) (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("get current user: %w", err)
	}
	flags := ""
	if inherit {
		flags = "OICI"
	}
	sddl := fmt.Sprintf(
		"D:P(A;%s;FA;;;SY)(A;%s;FA;;;BA)(A;%s;FA;;;%s)",
		flags, flags, flags, user.User.Sid.String(),
	)
	for _, reader := range readers {
		sddl += fmt.Sprintf("(A;%s;FR;;;%s)", flags, reader.String())
	}
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("build security descriptor: %w", err)
	}
	return descriptor, nil
}

func replaceFile(source, destination string) error {
	sourcePtr, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	destinationPtr, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(
		sourcePtr,
		destinationPtr,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH,
	)
}
