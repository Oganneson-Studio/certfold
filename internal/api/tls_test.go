package api

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"testing"
)

// TestServerAcceptsTLS12 checks that the HTTPS API accepts TLS 1.2, the most
// that Windows PowerShell 5.1 offers on older Windows to fetch install.ps1.
func TestServerAcceptsTLS12(t *testing.T) {
	deps := buildDeps(t)
	certPEM, keyPEM, err := deps.MiniCA.IssueServerCert([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	srv := New(deps, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil })
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(l, "", "") }()
	defer srv.Close()

	roots := x509.NewCertPool()
	roots.AddCert(deps.MiniCA.Cert())
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    roots,
		MaxVersion: tls.VersionTLS12,
	}}}
	defer client.CloseIdleConnections()
	resp, err := client.Get("https://" + l.Addr().String() + "/install.ps1")
	if err != nil {
		t.Fatalf("GET /install.ps1 over TLS 1.2: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.TLS.Version != tls.VersionTLS12 {
		t.Fatalf("status %d over %s, want 200 over TLS 1.2", resp.StatusCode, tls.VersionName(resp.TLS.Version))
	}
}
