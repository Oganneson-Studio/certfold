package enroll

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestPostEnrollRequiresTLS13 checks that enrollment keeps requiring TLS 1.3.
// sigils accepts TLS 1.2 as well, but only for the sake of the install
// scripts.
func TestPostEnrollRequiresTLS13(t *testing.T) {
	var reached atomic.Bool
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached.Store(true)
	}))
	ts.TLS = &tls.Config{MaxVersion: tls.VersionTLS12}
	ts.StartTLS()
	defer ts.Close()

	token := encodeTestToken(t, Token{ServerURL: ts.URL, Name: "web-1", CACert: testServerCertPEM(t, ts)})
	kc, err := GenerateKeyAndCSR("web-1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = PostEnroll(ts.URL, token, kc.CSRDER)
	if err == nil || !strings.Contains(err.Error(), "protocol version") {
		t.Fatalf("PostEnroll to a TLS 1.2 server: error = %v, want a protocol version error", err)
	}
	if reached.Load() {
		t.Fatal("the token reached a server over TLS 1.2")
	}
}
