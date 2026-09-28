package logging

import (
	"errors"
	"net/url"
	"testing"
)

func TestRedactURLQueries(t *testing.T) {
	// The error of a failed request of net/http quotes the URL with %q.
	requestErr := (&url.Error{
		Op:  "Get",
		URL: "https://www.duckdns.org/update?domains=example&token=0f9e-secret&txt=challenge",
		Err: errors.New("dial tcp: lookup www.duckdns.org: no such host"),
	}).Error()

	for _, tc := range []struct {
		name, in, want string
	}{
		{"url.Error", requestErr,
			`Get "https://www.duckdns.org/update?REDACTED": dial tcp: lookup www.duckdns.org: no such host`},
		{"several URLs",
			"retry http://a.example/x?k=1 after https://b.example:8443/y/z?AccessKeyId=AK&Signature=S%2B#top failed",
			"retry http://a.example/x?REDACTED after https://b.example:8443/y/z?REDACTED failed"},
		{"no query", `acme: error: 400 :: POST :: https://acme.example.com/acme/new-order :: urn:ietf:params:acme:error:malformed`,
			`acme: error: 400 :: POST :: https://acme.example.com/acme/new-order :: urn:ietf:params:acme:error:malformed`},
		{"single quote", "'https://h.example/p?a=b' refused", "'https://h.example/p?REDACTED' refused"},
		{"angle brackets", "<https://h.example/p?a=b>", "<https://h.example/p?REDACTED>"},
		{"end of line", "fetch https://h.example/p?a=b\nnext line", "fetch https://h.example/p?REDACTED\nnext line"},
		{"end of text", "fetch https://h.example/p?a=b", "fetch https://h.example/p?REDACTED"},
		{"upper case scheme", "HTTPS://H.EXAMPLE/P?A=B", "HTTPS://H.EXAMPLE/P?REDACTED"},
		{"empty query", "https://h.example/p? done", "https://h.example/p?REDACTED done"},
		{"other scheme", "ftp://h.example/p?a=b", "ftp://h.example/p?a=b"},
		{"no URL", "what? no", "what? no"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := RedactURLQueries(tc.in); got != tc.want {
				t.Fatalf("RedactURLQueries(%q)\n = %q\nwant %q", tc.in, got, tc.want)
			}
		})
	}
}
