package config

import (
	"strings"
	"testing"
)

func TestValidateClientName(t *testing.T) {
	for _, name := range []string{
		"web-1", "expiry-test", "revoke-test", // names the E2E suite enrolls
		"a", "0", "db01", strings.Repeat("a", 63),
	} {
		if err := ValidateClientName(name); err != nil {
			t.Errorf("ValidateClientName(%q) = %v, want nil", name, err)
		}
	}

	for _, name := range []string{
		"", "Web-1", "WEB-1", "web_1", "web.1", "web 1", "-web", "web-", "wéb",
		strings.Repeat("a", 64),
	} {
		err := ValidateClientName(name)
		if err == nil {
			t.Errorf("ValidateClientName(%q) = nil, want an error", name)
			continue
		}
		if !strings.Contains(err.Error(), "lowercase DNS label") {
			t.Errorf("ValidateClientName(%q) error does not state the rule: %v", name, err)
		}
	}
}
