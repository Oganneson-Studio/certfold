package client

import (
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestInvalidNameViewIsRequestedAgainAfterBackoff covers a server that keeps
// naming a certificate by a name config.ValidateCertificateName rejects. As
// with a bad bundle, the round fails and the etag does not advance: every
// later round asks for the whole view again, after the backoff, rather than
// waiting on an etag, which would clear the error with "round succeeded
// again" while the server still sends the name. The other certificates are
// delivered, and the invalid name is never downloaded.
func TestInvalidNameViewIsRequestedAgainAfterBackoff(t *testing.T) {
	setBackoff(t, 300*time.Millisecond, 300*time.Millisecond)
	good := newTestBundle(t, "api-prod")
	bad := newTestBundle(t, "api\x1b]0;pwned\a")
	fs := newFakeServer(good, bad)
	ts := httptest.NewServer(fs.handler())
	t.Cleanup(ts.Close)
	cfg := buildTestCfg(t, ts.URL)
	outPath := fullchainOutput(cfg, t.TempDir(), "api-prod")
	c := newTestClient(t, cfg)

	startRun(t, c)
	waitFor(t, "three sync requests", func() bool { return len(fs.syncRequests()) >= 3 })
	syncs := fs.syncRequests()
	for i := 1; i < 3; i++ {
		if syncs[i].ifNoneMatch != "" {
			t.Fatalf("sync request %d carried If-None-Match %q after a view with an invalid name", i+1, syncs[i].ifNoneMatch)
		}
		// The backoff is 300ms, less 10% of jitter at most.
		if gap := syncs[i].at.Sub(syncs[i-1].at); gap < 250*time.Millisecond {
			t.Fatalf("sync request %d came %v after the one before, want the backoff", i+1, gap)
		}
	}
	if fileContent(outPath) != good.FullchainPEM {
		t.Fatal("api-prod was not delivered")
	}
	if got := fs.bundleRequests(); slices.Contains(got, bad.Name) {
		t.Fatalf("bundle requests = %q, want no download of the invalid name", got)
	}
	if got := c.Status().LastError; !strings.Contains(got, `invalid certificate name "api\x1b]0;pwned\a"`) {
		t.Fatalf("LastError = %q, want the invalid name reported", got)
	}
}
