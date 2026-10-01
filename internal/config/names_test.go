package config

import (
	"strings"
	"testing"
	"unicode"
)

// Every name in server.yaml follows the rule of client names. certfolds sends
// the names of certificates to certfoldc, and prints those of CAs and DNS
// providers in cert list, cert show and its TUI, so the rule leaves no room
// for the control characters of an escape sequence. These are YAML escapes:
// raw ones would fail the YAML parser before the check.

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

// An invalid name of a CA or a DNS provider is reported alone: the paths of
// the other errors of its entry would quote it as it is. The entries these
// tests rename have another error to prove it.
func TestParseServer_CANames(t *testing.T) {
	for _, tc := range []struct {
		name, yaml, quoted string
	}{
		{"escape sequence", `"le\e]0;pwned\a"`, `"le\x1b]0;pwned\a"`},
		{"underscore", "lets_encrypt", `"lets_encrypt"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := strings.NewReplacer(
				"default_ca: letsencrypt", "default_ca: "+tc.yaml,
				"    letsencrypt:\n", "    "+tc.yaml+":\n",
				"    ca: letsencrypt", "    ca: "+tc.yaml,
				"https://acme-v02.api.letsencrypt.org/directory", "http://acme.example.com/directory",
			).Replace(validServerYAML)
			if n := strings.Count(src, tc.yaml); n != 3 {
				t.Fatalf("the fixture changed: the CA name is replaced %d times, want 3", n)
			}
			_, err := ParseServer([]byte(src))
			want := "acme.cas: invalid CA name " + tc.quoted + ": must be a lowercase DNS label"
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("CA name %s: error = %v, want %s", tc.yaml, err, want)
			}
			assertNoControlCharacters(t, err.Error())
		})
	}
}

func TestParseServer_DNSProviderNames(t *testing.T) {
	for _, tc := range []struct {
		name, yaml, quoted string
	}{
		{"escape sequence", `"cf\e]0;pwned\a"`, `"cf\x1b]0;pwned\a"`},
		{"underscore", "cf_main", `"cf_main"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := strings.NewReplacer(
				"  cf-main:\n", "  "+tc.yaml+":\n",
				"dns_provider: cf-main", "dns_provider: "+tc.yaml,
				`api_token: "tok"`, `zone: "example.com"`,
			).Replace(validServerYAML)
			if n := strings.Count(src, tc.yaml); n != 2 {
				t.Fatalf("the fixture changed: the DNS provider name is replaced %d times, want 2", n)
			}
			_, err := ParseServer([]byte(src))
			want := "dns_providers: invalid DNS provider name " + tc.quoted + ": must be a lowercase DNS label"
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("DNS provider name %s: error = %v, want %s", tc.yaml, err, want)
			}
			assertNoControlCharacters(t, err.Error())
		})
	}
}

// assertNoControlCharacters fails the test if text holds a control character
// other than the newlines between the errors of a ValidationError.
func assertNoControlCharacters(t *testing.T, text string) {
	t.Helper()
	if strings.ContainsFunc(text, func(r rune) bool { return r != '\n' && unicode.IsControl(r) }) {
		t.Fatalf("error keeps a control character: %q", text)
	}
}
