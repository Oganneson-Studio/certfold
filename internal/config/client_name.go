package config

import "fmt"

// ValidateClientName reports whether name is a valid client name: a lowercase
// DNS label of 1-63 characters from a-z, 0-9 and '-' that does not start or
// end with '-'. A client name is the CN of the client's certificate, its key in
// the database and the value subscriptions match exactly, so each client must
// have exactly one spelling.
func ValidateClientName(name string) error {
	valid := name != "" && len(name) <= 63 && name[0] != '-' && name[len(name)-1] != '-'
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			valid = false
		}
	}
	if !valid {
		return fmt.Errorf("invalid client name %q: must be a lowercase DNS label (1-63 characters from a-z, 0-9 and '-', not starting or ending with '-')", name)
	}
	return nil
}
