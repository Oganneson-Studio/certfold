package config

import "fmt"

// ValidateClientName reports whether name is a valid client name: a lowercase
// DNS label of 1-63 characters from a-z, 0-9 and '-' that does not start or
// end with '-'. A client name is the CN of the client's certificate, its key in
// the database and the value subscriptions match exactly, so each client must
// have exactly one spelling.
func ValidateClientName(name string) error {
	return validateName("client", name)
}

// ValidateCertificateName reports whether name is a valid certificate name,
// under the rule of client names. sigils sends the name of a certificate to
// every subscriber, which prints it to terminals and matches it exactly
// against the certificates of client.yaml: the rule leaves no room for the
// control characters of an escape sequence, nor for a second spelling.
func ValidateCertificateName(name string) error {
	return validateName("certificate", name)
}

// validateName checks name against the rule of client names, which every
// name in server.yaml follows as well: those of certificates, CAs and DNS
// providers. kind says which of these the error is about.
func validateName(kind, name string) error {
	valid := name != "" && len(name) <= 63 && name[0] != '-' && name[len(name)-1] != '-'
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			valid = false
		}
	}
	if !valid {
		return fmt.Errorf("invalid %s name %q: must be a lowercase DNS label (1-63 characters from a-z, 0-9 and '-', not starting or ending with '-')", kind, name)
	}
	return nil
}
