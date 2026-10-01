package config

import (
	"strconv"
	"strings"
	"testing"
)

func withPublicURL(publicURL string) string {
	return strings.Replace(validServerYAML, validDataDirLine,
		validDataDirLine+"\n  public_url: "+strconv.Quote(publicURL), 1)
}

// The install commands put server.public_url between single quotes for sh
// and PowerShell, so it may hold only ASCII characters that end or open no
// string in either.
func TestParseServer_PublicURLCharacters(t *testing.T) {
	for _, publicURL := range []string{
		"https://certfold.example.com",
		"https://certfold.example.com:8443/",
		"https://certfold.example.com/base/path",
		"https://10.0.0.1:8443",
		"https://[2001:db8::1]:8443",
		"https://[2001:db8::1]",
		"https://certfold.example.com:1",
		"https://certfold.example.com:65535",
	} {
		t.Run(publicURL, func(t *testing.T) {
			cfg, err := ParseServer([]byte(withPublicURL(publicURL)))
			if err != nil {
				t.Fatalf("public_url %q rejected: %v", publicURL, err)
			}
			if cfg.Server.PublicURL != publicURL {
				t.Fatalf("public_url = %q", cfg.Server.PublicURL)
			}
		})
	}

	for _, tc := range []struct {
		publicURL string
		char      string
	}{
		{"https://certfold.example.com/it's", `'\''`},
		{`https://certfold.example.com/"x"`, `'"'`},
		{"https://certfold.example.com/`id`", "'`'"},
		{"https://certfold.example.com/$HOME", `'$'`},
		{`https://certfold.example.com/a\b`, `'\\'`},
		{"https://certfold.example.com/a b", `' '`},
		// PowerShell ends a single-quoted string at U+2019 too.
		{"https://certfold.example.com/it’s", `'’'`},
		{"https://certfold.example.com/“x”", `'“'`},
		{"https://bücher.example.com", `'ü'`},
	} {
		t.Run(tc.publicURL, func(t *testing.T) {
			_, err := ParseServer([]byte(withPublicURL(tc.publicURL)))
			if want := "server.public_url: must not contain " + tc.char; err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("public_url %q: error = %v, want %s", tc.publicURL, err, want)
			}
		})
	}
}

// certfolds appends the paths of its endpoints to server.public_url, which must
// therefore name a host and hold nothing that a path cannot follow.
func TestParseServer_PublicURLStructure(t *testing.T) {
	for _, tc := range []struct {
		publicURL string
		want      string
	}{
		{"http://certfold.example.com", "must be an https URL"},
		{"certfold.example.com", "must be an https URL"},
		{"https:certfold.example.com", "must be an https URL"},
		{"https:///path", "must be an https URL"},
		{"https://certfold.example.com:https", "must be an https URL"},
		{"https://:8443", "must name a host"},
		{"https://user:pass@certfold.example.com", "must not contain user information"},
		{"https://certfold.example.com/?q=1", "must not have a query or a fragment"},
		{"https://certfold.example.com?", "must not have a query or a fragment"},
		{"https://certfold.example.com/#frag", "must not have a query or a fragment"},
		{"https://certfold.example.com#", "must not have a query or a fragment"},
		{"https://certfold.example.com:0", "must have a port from 1 to 65535"},
		{"https://certfold.example.com:65536", "must have a port from 1 to 65535"},
		{"https://certfold.example.com:", "must have a port from 1 to 65535"},
	} {
		t.Run(tc.publicURL, func(t *testing.T) {
			_, err := ParseServer([]byte(withPublicURL(tc.publicURL)))
			if want := "server.public_url: " + tc.want; err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("public_url %q: error = %v, want %s", tc.publicURL, err, want)
			}
		})
	}
}
