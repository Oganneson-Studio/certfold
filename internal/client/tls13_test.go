package client

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestMTLSRequestsRequireTLS13 checks that requests with the client identity
// keep requiring TLS 1.3. sigils accepts TLS 1.2 as well, but only for the
// sake of the install scripts.
func TestMTLSRequestsRequireTLS13(t *testing.T) {
	now := time.Now()
	authority := newTestIdentityCA(t, now)
	var reached atomic.Bool
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached.Store(true)
	}))
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{authority.serverTLSCertificate(t, now)},
		MaxVersion:   tls.VersionTLS12,
	}
	ts.StartTLS()
	defer ts.Close()

	cfg := buildTestCfg(t, ts.URL)
	withIdentity(t, cfg, authority, now, now.Add(24*time.Hour))
	client, err := buildHTTPClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get(ts.URL + "/v1/sync")
	if err == nil {
		resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "protocol version") {
		t.Fatalf("request to a TLS 1.2 server: error = %v, want a protocol version error", err)
	}
	if reached.Load() {
		t.Fatal("a request reached a server over TLS 1.2")
	}
}
