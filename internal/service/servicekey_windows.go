//go:build windows

package service

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// serviceKeyDACL gives SYSTEM and Administrators full control of a registry
// key and of the keys under it, and no one else any access. Protected, it
// takes nothing from the key above.
const serviceKeyDACL = "D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)"

// protectServiceKey leaves the registry key of the service name, which
// installing it created, to SYSTEM and Administrators. The key holds the
// Environment of the service, which gives the ${VAR}s of its configuration
// their values, such as credentials; it would otherwise take from Services
// read access for Users, where /etc/sysconfig/<name> on Linux is root's.
// The SCM runs as SYSTEM, and Get-Service and sc.exe ask the SCM, not the
// key. Its event source, under Services\EventLog, keeps its access.
func protectServiceKey(name string) error {
	key := `SYSTEM\CurrentControlSet\Services\` + name
	if err := protectRegistryKey(`MACHINE\` + key); err != nil {
		return fmt.Errorf("the %s service is installed, but every local user can still read its registry key, "+
			"whose Environment may hold credentials: %w; to leave the key to SYSTEM and Administrators, run in an elevated PowerShell: "+
			"$acl = New-Object Security.AccessControl.RegistrySecurity; $acl.SetSecurityDescriptorSddlForm('%s', 'Access'); "+
			"Set-Acl -Path 'HKLM:\\%s' -AclObject $acl", name, err, serviceKeyDACL, key)
	}
	return nil
}

// protectRegistryKey gives the registry key at path, named as
// SetNamedSecurityInfo names it (MACHINE\..., CURRENT_USER\...), the DACL
// serviceKeyDACL.
func protectRegistryKey(path string) error {
	descriptor, err := windows.SecurityDescriptorFromString(serviceKeyDACL)
	if err != nil {
		return fmt.Errorf("build security descriptor: %w", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read security descriptor DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_REGISTRY_KEY,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf("set DACL of %s: %w", path, err)
	}
	return nil
}
