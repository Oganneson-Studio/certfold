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

// TestNewServerLimits checks the server that sigils runs: every timeout that
// keeps a slow or idle peer on the public port from holding a connection, and
// the TLS 1.2 floor. TestServerAcceptsTLS12 shows that TLS 1.2 gets in; this
// shows that nothing older does.
func TestNewServerLimits(t *testing.T) {
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
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Fatalf("server timeouts are incomplete: header %s, read %s, write %s, idle %s",
			srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(l, "", "") }()
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(deps.MiniCA.Cert())
	conn, err := tls.Dial("tcp", l.Addr().String(), &tls.Config{
		RootCAs:    roots,
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS11,
	})
	if err == nil {
		version := conn.ConnectionState().Version
		conn.Close()
		t.Fatalf("server accepted %s, want at least TLS 1.2", tls.VersionName(version))
	}
}
