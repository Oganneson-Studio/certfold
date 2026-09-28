package config

import (
	"strings"
	"testing"
)

// sigils sends the names of certificates to sigilc, which prints them to
// terminals, so server.yaml takes only names under the rule of client names.
// The control characters are YAML escapes: raw ones would fail the YAML
// parser before the check.
func TestParseServer_CertificateNames(t *testing.T) {
	for _, tc := range []struct {
		name, yaml, quoted string
	}{
		{"escape sequence", `"api\e]0;pwned\a"`, `"api\x1b]0;pwned\a"`},
		{"C1 CSI", `"api\u009b31m"`, `"api\u009b31m"`},
		{"upper case", "Api-prod", `"Api-prod"`},
		{"dot", "api.example.com", `"api.example.com"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := strings.Replace(validServerYAML, "- name: api-prod", "- name: "+tc.yaml, 1)
			_, err := ParseServer([]byte(raw))
			want := "certificates[0].name: invalid certificate name " + tc.quoted + ": must be a lowercase DNS label"
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("name %s: error = %v, want %s", tc.yaml, err, want)
			}
		})
	}
}
