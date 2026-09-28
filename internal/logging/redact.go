package logging

import "regexp"

// urlQuery matches an http or https URL with a query: the part before the
// query, and the query, with the fragment if any, up to the end of the URL.
// Whitespace, a quote or an angle bracket ends a URL.
var urlQuery = regexp.MustCompile(`(?i)(https?://[^\s?"'<>]*)\?[^\s"'<>]*`)

// RedactURLQueries replaces the query of every http and https URL in s with
// "?REDACTED", and leaves the rest of s as it is. Some DNS provider APIs take
// credentials in the query, such as the token of DuckDNS, or the AccessKeyId
// and the signature of Alibaba Cloud, and the error of a failed request quotes
// its URL, as the log lines of lego may.
func RedactURLQueries(s string) string {
	return urlQuery.ReplaceAllString(s, "${1}?REDACTED")
}
