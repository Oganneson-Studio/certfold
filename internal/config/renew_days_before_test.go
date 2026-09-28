package config

import (
	"strings"
	"testing"
)

// renew_days_before once set when a certificate was renewed; the scheduler
// now renews it when a share of its lifetime is left. The field is rejected
// as unknown rather than ignored.
func TestParseServer_RenewDaysBeforeRejected(t *testing.T) {
	src := strings.Replace(validServerYAML, "    key_type: rsa4096\n", "    key_type: rsa4096\n    renew_days_before: 14\n", 1)
	_, err := ParseServer([]byte(src))
	if err == nil || !strings.Contains(err.Error(), "field renew_days_before not found") {
		t.Fatalf("expected renew_days_before to be rejected as an unknown field, got %v", err)
	}
}
