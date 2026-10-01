//go:build !windows

package service

// protectServiceKey does nothing outside Windows: there the environment of a
// service is a file of the operator's, such as /etc/sysconfig/<name>, and not
// part of what installing the service creates.
func protectServiceKey(string) error { return nil }
