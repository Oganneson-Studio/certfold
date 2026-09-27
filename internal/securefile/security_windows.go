//go:build windows

package securefile

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func secureDirectory(path string) error {
	return applyProtectedDACL(path, true)
}

func secureFile(path string) error {
	return applyProtectedDACL(path, false)
}

func applyProtectedDACL(path string, inherit bool) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("get current user: %w", err)
	}
	flags := ""
	if inherit {
		flags = "OICI"
	}
	sddl := fmt.Sprintf(
		"D:P(A;%s;FA;;;SY)(A;%s;FA;;;BA)(A;%s;FA;;;%s)",
		flags, flags, flags, user.User.Sid.String(),
	)
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("build security descriptor: %w", err)
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
