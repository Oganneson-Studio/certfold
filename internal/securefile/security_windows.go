//go:build windows

package securefile

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CreateTemp creates a new file in dir, named by replacing the last "*" in
// pattern with a random string as os.CreateTemp does, and opens it for reading
// and writing. The file is created with a protected DACL that grants full
// access to the trustees, which include the current user, and read access to
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

// privateDescriptor builds a protected DACL with full access for the trustees
// and read access for readers. For a directory, inherit passes every entry on
// to the files and directories created in it.
func privateDescriptor(inherit bool, readers ...*windows.SID) (*windows.SECURITY_DESCRIPTOR, error) {
	full, err := trustees()
	if err != nil {
		return nil, err
	}
	flags := ""
	if inherit {
		flags = "OICI"
	}
	sddl := "D:P"
	for _, trustee := range full {
		sddl += fmt.Sprintf("(A;%s;FA;;;%s)", flags, trustee.String())
	}
	for _, reader := range readers {
		sddl += fmt.Sprintf("(A;%s;FR;;;%s)", flags, reader.String())
	}
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("build security descriptor: %w", err)
	}
	return descriptor, nil
}

// trustees returns the accounts that get full control of what securefile
// creates: SYSTEM, Administrators and, when the process runs without
// Administrators enabled, its user. An elevated administrator reaches the
// files through Administrators. An entry for their own account would give
// the same access to their programs that run without elevation, and would
// be an account that the services, which run as LocalSystem, do not trust
// in the directories an administrator created when installing them.
func trustees() ([]*windows.SID, error) {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, fmt.Errorf("build the SID of SYSTEM: %w", err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, fmt.Errorf("build the SID of Administrators: %w", err)
	}
	// A null token checks the token of the calling thread.
	elevated, err := windows.Token(0).IsMember(admins)
	if err != nil {
		return nil, fmt.Errorf("check membership of Administrators: %w", err)
	}
	if elevated {
		return []*windows.SID{system, admins}, nil
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("get current user: %w", err)
	}
	return []*windows.SID{system, admins, user.User.Sid}, nil
}

// writeAccess is the access to a directory that lets an account put files or
// directories in it, delete or rename it or what is in it, or change its DACL
// or owner. 0x40 is FILE_DELETE_CHILD, which x/sys/windows does not define;
// FILE_WRITE_DATA and FILE_APPEND_DATA are FILE_ADD_FILE and
// FILE_ADD_SUBDIRECTORY on a directory.
const writeAccess windows.ACCESS_MASK = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | 0x40 |
	windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL

func checkDirectory(path string) error {
	err := checkAccess(path, writeAccess, "write to it or change its permissions")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func checkPrivateDirectory(path string) error {
	return checkAccess(path, ^windows.ACCESS_MASK(0), "access it")
}

// checkAccess returns an error unless a trustee owns the directory at path
// and its DACL grants no other account any of forbidden. what says what
// forbidden lets an account do, for the error.
func checkAccess(path string, forbidden windows.ACCESS_MASK, what string) error {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read the owner and DACL of %s: %w", path, err)
	}
	trusted, err := trustees()
	if err != nil {
		return err
	}
	return checkSecurity(path, descriptor, trusted, forbidden, what)
}

// checkSecurity checks descriptor, the security of the directory at path, as
// checkAccess describes. An entry for CREATOR OWNER passes: it grants nothing
// on the directory, and only on what its owner creates in it, which no one
// but a trustee may do. A folder created in C:\ProgramData inherits one.
func checkSecurity(path string, descriptor *windows.SECURITY_DESCRIPTOR, trusted []*windows.SID, forbidden windows.ACCESS_MASK, what string) error {
	owner, _, err := descriptor.Owner()
	if err != nil {
		return fmt.Errorf("read the owner of %s: %w", path, err)
	}
	if !slices.ContainsFunc(trusted, owner.Equals) {
		return fmt.Errorf("%s is owned by %s, but only %s may own it: its owner may have put files in it and may change who can write to it. Check the files in it, then run: icacls \"%s\" /setowner *S-1-5-32-544",
			path, accountName(owner), accountNames(trusted), path)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read the DACL of %s: %w", path, err)
	}
	var others []*windows.SID
	if dacl == nil {
		// A null DACL grants everyone full access.
		everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
		if err != nil {
			return fmt.Errorf("build the SID of Everyone: %w", err)
		}
		others = append(others, everyone)
	} else {
		creatorOwner, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerSid)
		if err != nil {
			return fmt.Errorf("build the SID of CREATOR OWNER: %w", err)
		}
		for i := range uint32(dacl.AceCount) {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(dacl, i, &ace); err != nil {
				return fmt.Errorf("read the DACL of %s: %w", path, err)
			}
			switch ace.Header.AceType {
			case windows.ACCESS_DENIED_ACE_TYPE:
				continue
			case windows.ACCESS_ALLOWED_ACE_TYPE:
			default:
				// The SID of other types is not where ACCESS_ALLOWED_ACE has it.
				return fmt.Errorf("%s has an access control entry of type %d, which sigil does not check; remove it", path, ace.Header.AceType)
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if ace.Mask&forbidden == 0 || sid.Equals(creatorOwner) || slices.ContainsFunc(trusted, sid.Equals) ||
				slices.ContainsFunc(others, sid.Equals) {
				continue
			}
			others = append(others, sid)
		}
	}
	if len(others) == 0 {
		return nil
	}
	names := make([]string, len(others))
	fix := fmt.Sprintf("icacls \"%s\" /inheritance:r /grant:r", path)
	for _, trustee := range trusted {
		fix += fmt.Sprintf(" *%s:(OI)(CI)F", trustee)
	}
	fix += " /remove:g"
	for i, other := range others {
		names[i] = accountName(other)
		fix += " *" + other.String()
	}
	return fmt.Errorf("%s lets %s %s, but only %s may. Check the files in it, then run: %s",
		path, strings.Join(names, ", "), what, accountNames(trusted), fix)
}

// accountName returns the name of the account sid stands for, or the SID when
// it has none.
func accountName(sid *windows.SID) string {
	account, domain, _, err := sid.LookupAccount("")
	switch {
	case err != nil:
		return sid.String()
	case domain == "":
		return account
	default:
		return domain + `\` + account
	}
}

// accountNames lists the names of sids for an error.
func accountNames(sids []*windows.SID) string {
	names := make([]string, len(sids))
	for i, sid := range sids {
		names[i] = accountName(sid)
	}
	if len(names) == 1 {
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
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
