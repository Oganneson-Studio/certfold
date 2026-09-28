package scheduler

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The error of a failed issuance can quote the URL of a request to the DNS
// provider API, whose query may hold credentials: the stored error, the one
// RenewNamed returns over IPC and the event keep the URL without its query.
func TestIssuanceErrorWithholdsURLQueries(t *testing.T) {
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	issuerErr := fmt.Errorf("dns provider duckdns: %w", &url.Error{
		Op:  "Get",
		URL: "https://www.duckdns.org/update?domains=example&token=0f9e-secret&txt=challenge",
		Err: errors.New("dial tcp: lookup www.duckdns.org: no such host"),
	})
	r := New(&mockIssuer{err: issuerErr}, db, nil, func() time.Time { return now })
	events := captureEvents(t)

	err := r.RenewNamed(context.Background(), static(minimalCfg("api-prod", nil)), "api-prod")
	const want = `dns provider duckdns: Get "https://www.duckdns.org/update?REDACTED": dial tcp: lookup www.duckdns.org: no such host`
	if err == nil || err.Error() != want {
		t.Fatalf("RenewNamed error = %v, want %s", err, want)
	}
	if !errors.Is(err, issuerErr) {
		t.Fatalf("RenewNamed error %q no longer wraps the issuer error", err)
	}
	if got := mustStatus(t, db, "api-prod").LastError; got != want {
		t.Fatalf("last_error = %q, want %q", got, want)
	}
	lines := eventLines(events)
	if !strings.Contains(strings.Join(lines, "\n"), "?REDACTED") {
		t.Fatalf("events do not report the failure: %q", lines)
	}
	for _, line := range lines {
		if strings.Contains(line, "0f9e-secret") {
			t.Fatalf("event keeps the query of the URL: %s", line)
		}
	}
}

// lastError withholds URL queries before it cuts the text: "?REDACTED" is
// longer than a short query, so cutting first could leave more than
// maxLastErrorBytes.
func TestLastErrorRedactsBeforeCutting(t *testing.T) {
	msg := strings.Repeat("x", maxLastErrorBytes-14) + " https://h/p?a" // maxLastErrorBytes long
	got := lastError(errors.New(msg))
	if len(got) > maxLastErrorBytes {
		t.Fatalf("lastError is %d bytes, want at most %d", len(got), maxLastErrorBytes)
	}
	if strings.Contains(got, "?a") {
		t.Fatalf("lastError keeps the query: ...%s", got[len(got)-20:])
	}
}
