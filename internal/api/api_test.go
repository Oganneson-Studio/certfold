package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/ca"
	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/enroll"
	"github.com/Oganneson-Studio/sigil/internal/store"
	"github.com/Oganneson-Studio/sigil/pkg/proto"
)

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

func mustOpenDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func mustBootstrapCA(t *testing.T) *ca.MiniCA {
	t.Helper()
	m, err := ca.Bootstrap(t.TempDir())
	if err != nil {
		t.Fatalf("bootstrap CA: %v", err)
	}
	return m
}

func buildDeps(t *testing.T) Deps {
	t.Helper()
	miniCA := mustBootstrapCA(t)
	db := mustOpenDB(t)
	enrollSvc := enroll.NewServer(db.Tokens, db.Clients, miniCA)
	return Deps{
		ServerCfg: &config.ServerConfig{
			Server: config.ServerSection{Listen: ":0", DataDir: t.TempDir()},
			Certificates: []config.CertificateSpec{
				{Name: "api-prod", CA: "letsencrypt", Domains: []string{"api.example.com"}, Subscribers: []string{"web-1"}},
			},
		},
		DB:           db,
		MiniCA:       miniCA,
		DataDir:      t.TempDir(),
		EnrollServer: enrollSvc,
		Changes:      NewChanges(),
	}
}

// makeClientCert issues a client cert from the mini-CA with the given CN.
func makeClientCert(t *testing.T, miniCA *ca.MiniCA, cn string) *tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrTpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTpl, priv)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	certDER, err := miniCA.Sign(csr, cn)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return &tlsCert
}

func makeEnrolledClientCert(t *testing.T, deps Deps, cn string) *tls.Certificate {
	t.Helper()
	clientCert := makeClientCert(t, deps.MiniCA, cn)
	if err := deps.DB.Clients.Upsert(context.Background(), &store.ClientRecord{
		Name:        cn,
		Fingerprint: ca.Fingerprint(clientCert.Certificate[0]),
		EnrolledAt:  time.Now().UTC(),
	}, nil); err != nil {
		t.Fatalf("record enrolled client: %v", err)
	}
	return clientCert
}

// simulateMTLS creates a request with a fake TLS state as if the client
// presented the given certificate.
func simulateMTLS(r *http.Request, clientCert *tls.Certificate) *http.Request {
	parsed, _ := x509.ParseCertificate(clientCert.Certificate[0])
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{parsed},
	}
	return r
}

// ---------------------------------------------------------------------------
// Public endpoints (no auth)
// ---------------------------------------------------------------------------

func TestInstallSh(t *testing.T) {
	deps := buildDeps(t)
	srv := NewInsecure(deps)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/install.sh", nil)
	srv.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "#!/bin/sh") {
		t.Errorf("install.sh missing shebang, got: %q", body[:min(80, len(body))])
	}
	if !strings.Contains(body, "enroll") {
		t.Errorf("install.sh missing enroll command")
	}
	if strings.Contains(body, "enroll --server") {
		t.Error("install.sh passes the unsupported --server flag")
	}
}

func TestInstallPs1(t *testing.T) {
	deps := buildDeps(t)
	srv := NewInsecure(deps)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/install.ps1?token=test-token", nil)
	srv.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "sigilc.exe") {
		t.Errorf("install.ps1 missing sigilc.exe reference")
	}
	if !strings.Contains(rec.Body.String(), `param([string]$Token = "test-token")`) {
		t.Errorf("install.ps1 did not embed the token query parameter")
	}
	if strings.Contains(rec.Body.String(), "enroll --server") {
		t.Error("install.ps1 passes the unsupported --server flag")
	}
	if !strings.Contains(rec.Body.String(), `"ARM64" { "arm64" }`) {
		t.Error("install.ps1 does not detect Windows ARM64")
	}
}

func TestInstallPs1_RejectsPowerShellInjection(t *testing.T) {
	deps := buildDeps(t)
	srv := NewInsecure(deps)
	rec := httptest.NewRecorder()
	payload := `$([System.Environment]::MachineName)`
	req := httptest.NewRequest(http.MethodGet, "/install.ps1?token="+url.QueryEscape(payload), nil)
	srv.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if strings.Contains(rec.Body.String(), payload) {
		t.Fatal("install.ps1 reflected executable PowerShell input")
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

func TestEnrollRejectsOversizedBody(t *testing.T) {
	deps := buildDeps(t)
	srv := NewInsecure(deps)
	rec := httptest.NewRecorder()
	body := `{"token":"` + strings.Repeat("a", maxAPIRequestBody) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", strings.NewReader(body))
	srv.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestServerHasResourceTimeouts(t *testing.T) {
	srv := NewInsecure(buildDeps(t))
	if srv.ReadHeaderTimeout == 0 || srv.ReadTimeout == 0 || srv.WriteTimeout == 0 || srv.IdleTimeout == 0 {
		t.Fatalf("server timeouts are incomplete: %+v", srv)
	}
}

func TestDownloadSigilc_NotFound(t *testing.T) {
	deps := buildDeps(t)
	srv := NewInsecure(deps)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/download/sigilc?os=linux&arch=amd64", nil)
	srv.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestDownloadSigilc_Success(t *testing.T) {
	deps := buildDeps(t)
	binDir := filepath.Join(deps.DataDir, "binaries")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir binaries: %v", err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "sigilc-linux-amd64"), []byte("binary"), 0o755); err != nil {
		t.Fatalf("write binary: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/download/sigilc?os=linux&arch=amd64", nil)
	NewInsecure(deps).Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "binary" {
		t.Fatalf("unexpected body %q", rec.Body.String())
	}
}

func TestDownloadSigilc_RejectsPathTraversal(t *testing.T) {
	deps := buildDeps(t)
	secretPath := filepath.Join(deps.DataDir, "ca", "ca.key")
	if err := os.MkdirAll(filepath.Dir(secretPath), 0o700); err != nil {
		t.Fatalf("mkdir secret dir: %v", err)
	}
	if err := os.WriteFile(secretPath, []byte("private-ca-key"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/download/sigilc?os=linux&arch=../../../ca/ca.key", nil)
	NewInsecure(deps).Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "private-ca-key") {
		t.Fatal("response leaked a file outside the binaries directory")
	}
}

// ---------------------------------------------------------------------------
// POST /v1/enroll
// ---------------------------------------------------------------------------

func TestEnroll_Success(t *testing.T) {
	deps := buildDeps(t)
	ctx := context.Background()

	// Create token via enroll.Server (real path — base64 payload + secret hash).
	tokenStr, err := deps.EnrollServer.Create(ctx, "https://sigil.example.com:8443", "web-1", time.Hour)
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "web-1"}}, priv)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	body, _ := json.Marshal(proto.EnrollRequest{Token: tokenStr, CSR: string(csrPEM)})
	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	NewInsecure(deps).Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, body: %s", rec.Code, rec.Body.String())
	}
	var resp proto.EnrollResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.CACert == "" || resp.ClientCert == "" {
		t.Error("response missing CA or client cert")
	}
}

func TestEnroll_InvalidToken(t *testing.T) {
	deps := buildDeps(t)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, priv)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// "bad-token" is not valid base64url JSON — should get 401.
	body, _ := json.Marshal(proto.EnrollRequest{Token: "bad-token", CSR: string(csrPEM)})
	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	NewInsecure(deps).Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestEnroll_ExpiredToken(t *testing.T) {
	deps := buildDeps(t)
	ctx := context.Background()

	// Create an already-expired token via enroll.Server (negative TTL).
	tokenStr, err := deps.EnrollServer.Create(ctx, "https://sigil.example.com:8443", "web-1", -time.Hour)
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, priv)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	body, _ := json.Marshal(proto.EnrollRequest{Token: tokenStr, CSR: string(csrPEM)})
	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	NewInsecure(deps).Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// TestEnroll_FullPathThroughEnrollServer is the core integration test that
// covers the full enroll flow: Create token → POST /v1/enroll → verify DB state.
// This is the test that M6 lacked; it would have caught the token lookup bug.
func TestEnroll_FullPathThroughEnrollServer(t *testing.T) {
	deps := buildDeps(t)
	ctx := context.Background()

	// Step 1: create a real token (stores secretHash in DB).
	tokenStr, err := deps.EnrollServer.Create(ctx, "https://sigil.example.com:8443", "web-1", time.Hour)
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}

	// Step 2: construct a real CSR.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "web-1"}}, priv)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// Step 3: POST /v1/enroll with the real token.
	reqBody, _ := json.Marshal(proto.EnrollRequest{Token: tokenStr, CSR: string(csrPEM)})
	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	NewInsecure(deps).Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("enroll status: got %d, body: %s", rec.Code, rec.Body.String())
	}

	// Step 4: verify response fields.
	var resp proto.EnrollResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.CACert == "" {
		t.Error("response missing ca_cert")
	}
	if resp.ClientCert == "" {
		t.Error("response missing client_cert")
	}

	// Step 5: verify the returned client cert is signed by our mini-CA.
	block, _ := pem.Decode([]byte(resp.ClientCert))
	if block == nil {
		t.Fatal("client_cert is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse client cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(deps.MiniCA.Cert())
	opts := x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if _, err := cert.Verify(opts); err != nil {
		t.Errorf("client cert not verifiable by CA: %v", err)
	}
	if cert.Subject.CommonName != "web-1" {
		t.Errorf("client cert CN: got %q, want %q", cert.Subject.CommonName, "web-1")
	}

	// Step 6: verify token is marked used in DB (replay must fail).
	priv2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER2, _ := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "web-1"}}, priv2)
	csrPEM2 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER2})
	reqBody2, _ := json.Marshal(proto.EnrollRequest{Token: tokenStr, CSR: string(csrPEM2)})
	req2 := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(reqBody2))
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	NewInsecure(deps).Handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("replay should return 401, got %d", rec2.Code)
	}

	// Step 7: verify client record was written to DB.
	cl, err := deps.DB.Clients.Get(ctx, "web-1", nil)
	if err != nil {
		t.Fatalf("client not in DB after enroll: %v", err)
	}
	if cl.Name != "web-1" {
		t.Errorf("client name: got %q", cl.Name)
	}
	if cl.Fingerprint == "" {
		t.Error("client fingerprint should be set")
	}
}

func TestEnroll_RejectWithClientCert(t *testing.T) {
	deps := buildDeps(t)
	clientCert := makeClientCert(t, deps.MiniCA, "web-1")

	body, _ := json.Marshal(proto.EnrollRequest{Token: "x", CSR: "x"})
	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(body))
	req = simulateMTLS(req, clientCert)
	rec := httptest.NewRecorder()
	NewInsecure(deps).Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when mTLS cert present on enroll, got %d", rec.Code)
	}
}

func TestRenewIdentityStagesThenPromotesOnFirstUse(t *testing.T) {
	deps := buildDeps(t)
	oldIdentity := makeEnrolledClientCert(t, deps, "web-1")
	oldFingerprint := ca.Fingerprint(oldIdentity.Certificate[0])

	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored-by-server"}}, newKey)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	body, err := json.Marshal(proto.RenewIdentityRequest{CSR: string(csrPEM)})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/identity/renew", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = simulateMTLS(req, oldIdentity)
	rec := httptest.NewRecorder()
	NewInsecure(deps).Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("renew status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var response proto.RenewIdentityResponse
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(newKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	newIdentity, err := tls.X509KeyPair([]byte(response.ClientCert), keyPEM)
	if err != nil {
		t.Fatalf("renewed certificate does not match CSR key: %v", err)
	}
	newParsed, err := x509.ParseCertificate(newIdentity.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if newParsed.Subject.CommonName != "web-1" {
		t.Fatalf("renewed CN = %q, want web-1", newParsed.Subject.CommonName)
	}
	newFingerprint := ca.Fingerprint(newIdentity.Certificate[0])

	staged, err := deps.DB.Clients.Get(context.Background(), "web-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if staged.Fingerprint != oldFingerprint || staged.PendingFingerprint != newFingerprint {
		t.Fatalf("unexpected staged client: %+v", staged)
	}

	// A lost response must not revoke the old identity.
	oldReq := simulateMTLS(httptest.NewRequest(http.MethodGet, "/v1/sync", nil), oldIdentity)
	oldRec := httptest.NewRecorder()
	NewInsecure(deps).Handler.ServeHTTP(oldRec, oldReq)
	if oldRec.Code != http.StatusOK {
		t.Fatalf("old identity rejected before promotion: %d", oldRec.Code)
	}

	// First use of the new identity promotes it atomically.
	newReq := simulateMTLS(httptest.NewRequest(http.MethodGet, "/v1/sync", nil), &newIdentity)
	newRec := httptest.NewRecorder()
	NewInsecure(deps).Handler.ServeHTTP(newRec, newReq)
	if newRec.Code != http.StatusOK {
		t.Fatalf("new identity status = %d, body = %s", newRec.Code, newRec.Body.String())
	}
	promoted, err := deps.DB.Clients.Get(context.Background(), "web-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if promoted.Fingerprint != newFingerprint || promoted.PendingFingerprint != "" {
		t.Fatalf("unexpected promoted client: %+v", promoted)
	}

	revokedReq := simulateMTLS(httptest.NewRequest(http.MethodGet, "/v1/sync", nil), oldIdentity)
	revokedRec := httptest.NewRecorder()
	NewInsecure(deps).Handler.ServeHTTP(revokedRec, revokedReq)
	if revokedRec.Code != http.StatusUnauthorized {
		t.Fatalf("old identity status after promotion = %d, want 401", revokedRec.Code)
	}
}

func TestRenewIdentityRejectsInvalidCSR(t *testing.T) {
	deps := buildDeps(t)
	identity := makeEnrolledClientCert(t, deps, "web-1")
	body, _ := json.Marshal(proto.RenewIdentityRequest{CSR: "not pem"})
	req := httptest.NewRequest(http.MethodPost, "/v1/identity/renew", bytes.NewReader(body))
	req = simulateMTLS(req, identity)
	rec := httptest.NewRecorder()
	NewInsecure(deps).Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// GET /v1/certificates — requires mTLS
// ---------------------------------------------------------------------------

func TestListCertificates_NoMTLS(t *testing.T) {
	deps := buildDeps(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/certificates", nil)
	rec := httptest.NewRecorder()
	NewInsecure(deps).Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without mTLS, got %d", rec.Code)
	}
}

func TestListCertificates_WithMTLS(t *testing.T) {
	deps := buildDeps(t)

	// Seed a certificate record that web-1 is subscribed to.
	_ = deps.DB.Certs.Upsert(context.Background(), &store.CertRecord{
		Name:            "api-prod",
		CA:              "letsencrypt",
		Domains:         []string{"api.example.com"},
		SpecFingerprint: config.CertificateSpecFingerprint(deps.ServerCfg, deps.ServerCfg.Certificates[0]),
		Fingerprint:     "sha256:AABB",
		NotAfter:        time.Now().Add(90 * 24 * time.Hour),
		UpdatedAt:       time.Now(),
	}, nil)

	clientCert := makeEnrolledClientCert(t, deps, "web-1")
	req := httptest.NewRequest(http.MethodGet, "/v1/certificates", nil)
	req = simulateMTLS(req, clientCert)
	rec := httptest.NewRecorder()
	NewInsecure(deps).Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, body: %s", rec.Code, rec.Body.String())
	}
	var certs []proto.CertSummary
	if err := json.NewDecoder(rec.Body).Decode(&certs); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(certs) != 1 || certs[0].Name != "api-prod" {
		t.Errorf("expected [api-prod], got %v", certs)
	}
}

func TestListCertificates_FilterBySubscriber(t *testing.T) {
	deps := buildDeps(t)

	// web-2 is NOT in subscribers for api-prod.
	clientCert := makeEnrolledClientCert(t, deps, "web-2")
	req := httptest.NewRequest(http.MethodGet, "/v1/certificates", nil)
	req = simulateMTLS(req, clientCert)
	rec := httptest.NewRecorder()
	NewInsecure(deps).Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d", rec.Code)
	}
	var certs []proto.CertSummary
	_ = json.NewDecoder(rec.Body).Decode(&certs)
	if len(certs) != 0 {
		t.Errorf("web-2 should see 0 certs, got %d", len(certs))
	}
}

func TestSubscriptionMatchIsExact(t *testing.T) {
	deps := buildDeps(t)
	if err := deps.DB.Certs.Upsert(context.Background(), &store.CertRecord{
		Name:            "api-prod",
		CA:              "letsencrypt",
		Domains:         []string{"api.example.com"},
		SpecFingerprint: config.CertificateSpecFingerprint(deps.ServerCfg, deps.ServerCfg.Certificates[0]),
		FullchainPEM:    "chain",
		KeyPEM:          "private-key-for-web-1",
		UpdatedAt:       time.Now(),
	}, nil); err != nil {
		t.Fatalf("seed certificate: %v", err)
	}

	// A client enrolled under another spelling of the subscriber "web-1" is a
	// different client and must not receive its certificates.
	clientCert := makeEnrolledClientCert(t, deps, "WEB-1")
	handler := NewInsecure(deps).Handler

	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, simulateMTLS(httptest.NewRequest(http.MethodGet, "/v1/certificates", nil), clientCert))
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d", listRec.Code)
	}
	var certs []proto.CertSummary
	if err := json.NewDecoder(listRec.Body).Decode(&certs); err != nil {
		t.Fatal(err)
	}
	if len(certs) != 0 {
		t.Fatalf("WEB-1 sees certificates subscribed by web-1: %+v", certs)
	}

	syncRec := httptest.NewRecorder()
	handler.ServeHTTP(syncRec, syncRequest(clientCert, ""))
	if syncRec.Code != http.StatusOK {
		t.Fatalf("sync status = %d", syncRec.Code)
	}
	if view := decodeView(t, syncRec); len(view) != 0 {
		t.Fatalf("WEB-1 syncs certificates subscribed by web-1: %+v", view)
	}

	bundleRec := httptest.NewRecorder()
	handler.ServeHTTP(bundleRec, simulateMTLS(httptest.NewRequest(http.MethodGet, "/v1/certificates/api-prod/bundle", nil), clientCert))
	if bundleRec.Code != http.StatusNotFound || strings.Contains(bundleRec.Body.String(), "private-key-for-web-1") {
		t.Fatalf("bundle status = %d, body = %s", bundleRec.Code, bundleRec.Body.String())
	}
}

func TestListCertificatesReflectsRuntimeSubscriptionReload(t *testing.T) {
	deps := buildDeps(t)
	var current atomic.Pointer[config.ServerConfig]
	current.Store(deps.ServerCfg)
	deps.CurrentServer = current.Load
	_ = deps.DB.Certs.Upsert(context.Background(), &store.CertRecord{
		Name:            "api-prod",
		CA:              "letsencrypt",
		Domains:         []string{"api.example.com"},
		SpecFingerprint: config.CertificateSpecFingerprint(deps.ServerCfg, deps.ServerCfg.Certificates[0]),
		Fingerprint:     "sha256:AABB",
		NotAfter:        time.Now().Add(90 * 24 * time.Hour),
		UpdatedAt:       time.Now(),
	}, nil)
	clientCert := makeEnrolledClientCert(t, deps, "web-2")
	handler := NewInsecure(deps).Handler

	list := func() []proto.CertSummary {
		req := simulateMTLS(httptest.NewRequest(http.MethodGet, "/v1/certificates", nil), clientCert)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var certs []proto.CertSummary
		if err := json.NewDecoder(rec.Body).Decode(&certs); err != nil {
			t.Fatal(err)
		}
		return certs
	}

	if got := list(); len(got) != 0 {
		t.Fatalf("certificates before reload = %+v", got)
	}
	next := *deps.ServerCfg
	next.Certificates = append([]config.CertificateSpec(nil), deps.ServerCfg.Certificates...)
	next.Certificates[0].Subscribers = []string{"web-1", "web-2"}
	current.Store(&next)
	if got := list(); len(got) != 1 || got[0].Name != "api-prod" {
		t.Fatalf("certificates after reload = %+v", got)
	}
}

// ---------------------------------------------------------------------------
// GET /v1/sync — requires mTLS
// ---------------------------------------------------------------------------

// setSyncMaxWait sets how long GET /v1/sync waits, for the rest of the test.
// A test that changes it must collect every sync it started before it ends.
func setSyncMaxWait(t *testing.T, d time.Duration) {
	t.Helper()
	previous := syncMaxWait
	syncMaxWait = d
	t.Cleanup(func() { syncMaxWait = previous })
}

// seedCert stores material for spec, recorded as issued under cfg.
func seedCert(t *testing.T, deps Deps, cfg *config.ServerConfig, spec config.CertificateSpec, fingerprint string) {
	t.Helper()
	if err := deps.DB.Certs.Upsert(context.Background(), &store.CertRecord{
		Name:            spec.Name,
		CA:              spec.CA,
		Domains:         spec.Domains,
		SpecFingerprint: config.CertificateSpecFingerprint(cfg, spec),
		FullchainPEM:    "chain-" + spec.Name,
		KeyPEM:          "private-key-" + spec.Name,
		Fingerprint:     fingerprint,
		NotAfter:        time.Now().Add(90 * 24 * time.Hour),
		UpdatedAt:       time.Now(),
	}, nil); err != nil {
		t.Fatalf("seed certificate %s: %v", spec.Name, err)
	}
}

// syncRequest is GET /v1/sync from identity, with If-None-Match unless etag
// is empty.
func syncRequest(identity *tls.Certificate, etag string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/v1/sync", nil)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	return simulateMTLS(req, identity)
}

func decodeView(t *testing.T, rec *httptest.ResponseRecorder) []proto.CertSummary {
	t.Helper()
	var view []proto.CertSummary
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode view %q: %v", rec.Body.String(), err)
	}
	return view
}

// syncView fetches the current view of identity and its ETag.
func syncView(t *testing.T, handler http.Handler, identity *tls.Certificate) ([]proto.CertSummary, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, syncRequest(identity, ""))
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") == "" {
		t.Fatalf("sync status = %d, ETag = %q, body = %s", rec.Code, rec.Header().Get("ETag"), rec.Body.String())
	}
	return decodeView(t, rec), rec.Header().Get("ETag")
}

// startSync serves req in the background. Its answer arrives on the channel
// once the handler returns.
func startSync(handler http.Handler, req *http.Request) <-chan *httptest.ResponseRecorder {
	answered := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		answered <- rec
	}()
	return answered
}

// assertWaiting fails the test if a sync started in the background answered
// while nothing changed. Tests call it before they change the view, so that
// the change normally reaches a waiting request rather than its first read.
func assertWaiting(t *testing.T, answered <-chan *httptest.ResponseRecorder) {
	t.Helper()
	select {
	case rec := <-answered:
		t.Fatalf("sync answered %d although nothing changed", rec.Code)
	case <-time.After(100 * time.Millisecond):
	}
}

// awaitSync returns the answer of a sync started in the background.
func awaitSync(t *testing.T, answered <-chan *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	select {
	case rec := <-answered:
		return rec
	case <-time.After(5 * time.Second):
		t.Fatal("sync did not answer within 5s")
		return nil
	}
}

func TestSync_NoMTLS(t *testing.T) {
	deps := buildDeps(t)
	rec := httptest.NewRecorder()
	NewInsecure(deps).Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/sync", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without mTLS, got %d", rec.Code)
	}
}

func TestSyncListsSubscribedCurrentCertificatesWithETag(t *testing.T) {
	deps := buildDeps(t)
	cfg := deps.ServerCfg
	cfg.Certificates = append(cfg.Certificates,
		config.CertificateSpec{Name: "db-prod", CA: "letsencrypt", Domains: []string{"db.example.com"}, Subscribers: []string{"web-2"}},
		config.CertificateSpec{Name: "edge-prod", CA: "letsencrypt", Domains: []string{"edge.example.com"}, Subscribers: []string{"web-1"}},
	)
	seedCert(t, deps, cfg, cfg.Certificates[0], "sha256:API")
	seedCert(t, deps, cfg, cfg.Certificates[1], "sha256:DB")
	// Issued before the key type of edge-prod changed.
	stale := cfg.Certificates[2]
	stale.KeyType = "rsa2048"
	seedCert(t, deps, cfg, stale, "sha256:EDGE")

	identity := makeEnrolledClientCert(t, deps, "web-1")
	rec := httptest.NewRecorder()
	NewInsecure(deps).Handler.ServeHTTP(rec, syncRequest(identity, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	sum := sha256.Sum256(rec.Body.Bytes())
	if got, want := rec.Header().Get("ETag"), `"`+base64.RawURLEncoding.EncodeToString(sum[:])+`"`; got != want {
		t.Fatalf("ETag = %s, want %s, the hash of the body", got, want)
	}
	if view := decodeView(t, rec); len(view) != 1 || view[0].Name != "api-prod" || view[0].Fingerprint != "sha256:API" {
		t.Fatalf("view = %+v, want only api-prod", view)
	}
}

func TestSyncWaitsOnlyForItsExactETag(t *testing.T) {
	setSyncMaxWait(t, time.Minute)
	deps := buildDeps(t)
	identity := makeEnrolledClientCert(t, deps, "web-1")
	handler := NewInsecure(deps).Handler
	_, etag := syncView(t, handler, identity)

	for _, ifNoneMatch := range [][]string{
		{"W/" + etag},
		{"*"},
		{etag + `, "other"`},
		{`"other", ` + etag},
		{strings.Trim(etag, `"`)},
		// A list over several field lines.
		{etag, `"other"`},
	} {
		req := syncRequest(identity, "")
		for _, value := range ifNoneMatch {
			req.Header.Add("If-None-Match", value)
		}
		rec := awaitSync(t, startSync(handler, req))
		if rec.Code != http.StatusOK || rec.Header().Get("ETag") != etag {
			t.Errorf("If-None-Match %q: status = %d, ETag = %s; want 200 with %s", ifNoneMatch, rec.Code, rec.Header().Get("ETag"), etag)
		}
	}
}

func TestSyncAnswersNotModifiedAfterWaitingOut(t *testing.T) {
	setSyncMaxWait(t, 300*time.Millisecond)
	deps := buildDeps(t)
	seedCert(t, deps, deps.ServerCfg, deps.ServerCfg.Certificates[0], "sha256:API")
	identity := makeEnrolledClientCert(t, deps, "web-1")
	handler := NewInsecure(deps).Handler
	_, etag := syncView(t, handler, identity)

	start := time.Now()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, syncRequest(identity, etag))
	elapsed := time.Since(start)
	if rec.Code != http.StatusNotModified || rec.Header().Get("ETag") != etag || rec.Body.Len() != 0 {
		t.Fatalf("status = %d, ETag = %s, body = %q; want 304 with ETag %s and no body",
			rec.Code, rec.Header().Get("ETag"), rec.Body.String(), etag)
	}
	if elapsed < syncMaxWait {
		t.Fatalf("answered after %s, before waiting out %s", elapsed, syncMaxWait)
	}
}

func TestSyncAnswersStoredCertificateAtOnce(t *testing.T) {
	setSyncMaxWait(t, time.Minute)
	deps := buildDeps(t)
	spec := deps.ServerCfg.Certificates[0]
	seedCert(t, deps, deps.ServerCfg, spec, "sha256:OLD")
	identity := makeEnrolledClientCert(t, deps, "web-1")
	handler := NewInsecure(deps).Handler
	_, etag := syncView(t, handler, identity)

	answered := startSync(handler, syncRequest(identity, etag))
	assertWaiting(t, answered)
	seedCert(t, deps, deps.ServerCfg, spec, "sha256:NEW")
	deps.Changes.Notify()
	rec := awaitSync(t, answered)
	if rec.Code != http.StatusOK || rec.Header().Get("ETag") == etag {
		t.Fatalf("status = %d, ETag = %s; want 200 with a new ETag", rec.Code, rec.Header().Get("ETag"))
	}
	if view := decodeView(t, rec); len(view) != 1 || view[0].Fingerprint != "sha256:NEW" {
		t.Fatalf("view = %+v, want the renewed api-prod", view)
	}
}

// A client must not learn anything about certificates it does not subscribe
// to, including when they change. Their changes still wake its request, which
// must keep its deadline: the certificates of other clients keep changing
// here until it answers.
func TestSyncKeepsWaitingThroughOtherClientsChanges(t *testing.T) {
	setSyncMaxWait(t, time.Second)
	deps := buildDeps(t)
	cfg := deps.ServerCfg
	cfg.Certificates = append(cfg.Certificates, config.CertificateSpec{
		Name: "db-prod", CA: "letsencrypt", Domains: []string{"db.example.com"}, Subscribers: []string{"web-2"},
	})
	seedCert(t, deps, cfg, cfg.Certificates[0], "sha256:API")
	identity := makeEnrolledClientCert(t, deps, "web-1")
	handler := NewInsecure(deps).Handler
	_, etag := syncView(t, handler, identity)

	start := time.Now()
	answered := startSync(handler, syncRequest(identity, etag))
	assertWaiting(t, answered)
	changes := time.NewTicker(100 * time.Millisecond)
	defer changes.Stop()
	timeout := time.After(5 * time.Second)
	for i := 0; ; i++ {
		select {
		case rec := <-answered:
			if rec.Code != http.StatusNotModified || rec.Header().Get("ETag") != etag {
				t.Fatalf("status = %d, ETag = %s; want 304 with %s", rec.Code, rec.Header().Get("ETag"), etag)
			}
			if elapsed := time.Since(start); elapsed < syncMaxWait {
				t.Fatalf("answered after %s, before waiting out %s", elapsed, syncMaxWait)
			}
			return
		case <-changes.C:
			seedCert(t, deps, cfg, cfg.Certificates[1], fmt.Sprintf("sha256:DB-%d", i))
			deps.Changes.Notify()
		case <-timeout:
			t.Fatal("sync did not answer within 5s while other certificates kept changing")
		}
	}
}

func TestSyncAnswersReloadedSubscriptionAtOnce(t *testing.T) {
	setSyncMaxWait(t, time.Minute)
	deps := buildDeps(t)
	var current atomic.Pointer[config.ServerConfig]
	current.Store(deps.ServerCfg)
	deps.CurrentServer = current.Load
	seedCert(t, deps, deps.ServerCfg, deps.ServerCfg.Certificates[0], "sha256:API")
	identity := makeEnrolledClientCert(t, deps, "web-2")
	handler := NewInsecure(deps).Handler
	view, etag := syncView(t, handler, identity)
	if len(view) != 0 {
		t.Fatalf("view before reload = %+v", view)
	}

	answered := startSync(handler, syncRequest(identity, etag))
	assertWaiting(t, answered)
	next := *deps.ServerCfg
	next.Certificates = append([]config.CertificateSpec(nil), deps.ServerCfg.Certificates...)
	next.Certificates[0].Subscribers = []string{"web-1", "web-2"}
	current.Store(&next)
	deps.Changes.Notify()
	rec := awaitSync(t, answered)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if view := decodeView(t, rec); len(view) != 1 || view[0].Name != "api-prod" {
		t.Fatalf("view after reload = %+v", view)
	}
}

// A reload published while a waiting sync reads the configuration must still
// wake it, which holds only if the sync took its wake-up channel before the
// read. CurrentServer publishes the new configuration and notifies during that
// read, and still returns the old one.
func TestSyncWakesForReloadPublishedDuringItsRead(t *testing.T) {
	setSyncMaxWait(t, time.Minute)
	deps := buildDeps(t)
	next := *deps.ServerCfg
	next.Certificates = append([]config.CertificateSpec(nil), deps.ServerCfg.Certificates...)
	next.Certificates[0].Subscribers = []string{"web-1", "web-2"}
	var current atomic.Pointer[config.ServerConfig]
	current.Store(deps.ServerCfg)
	var reloadDuringRead atomic.Bool
	changes := deps.Changes
	deps.CurrentServer = func() *config.ServerConfig {
		cfg := current.Load()
		if reloadDuringRead.CompareAndSwap(true, false) {
			current.Store(&next)
			changes.Notify()
		}
		return cfg
	}
	seedCert(t, deps, deps.ServerCfg, deps.ServerCfg.Certificates[0], "sha256:API")
	identity := makeEnrolledClientCert(t, deps, "web-2")
	handler := NewInsecure(deps).Handler
	view, etag := syncView(t, handler, identity)
	if len(view) != 0 {
		t.Fatalf("view before reload = %+v", view)
	}

	reloadDuringRead.Store(true)
	rec := awaitSync(t, startSync(handler, syncRequest(identity, etag)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if view := decodeView(t, rec); len(view) != 1 || view[0].Name != "api-prod" {
		t.Fatalf("view after reload = %+v", view)
	}
}

func TestSyncRejectsClientRemovedWhileWaiting(t *testing.T) {
	setSyncMaxWait(t, time.Minute)
	deps := buildDeps(t)
	cfg := deps.ServerCfg
	cfg.Certificates = append(cfg.Certificates, config.CertificateSpec{
		Name: "payroll-prod", CA: "letsencrypt", Domains: []string{"payroll.example.com"}, Subscribers: []string{"web-1"},
	})
	seedCert(t, deps, cfg, cfg.Certificates[0], "sha256:API")
	identity := makeEnrolledClientCert(t, deps, "web-1")
	handler := NewInsecure(deps).Handler
	_, etag := syncView(t, handler, identity)

	answered := startSync(handler, syncRequest(identity, etag))
	assertWaiting(t, answered)
	if err := deps.DB.Clients.Delete(context.Background(), "web-1", nil); err != nil {
		t.Fatalf("delete client: %v", err)
	}
	seedCert(t, deps, cfg, cfg.Certificates[1], "sha256:PAYROLL")
	deps.Changes.Notify()
	rec := awaitSync(t, answered)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if body := rec.Body.String(); strings.Contains(body, "payroll-prod") || strings.Contains(body, "api-prod") {
		t.Fatalf("401 carries the view: %s", body)
	}
	if got := rec.Header().Get("ETag"); got != "" {
		t.Fatalf("401 carries the ETag of the new view: %s", got)
	}
}

// Once a renewed identity is in use, a sync still waiting under the one it
// replaced must not receive the client's view.
func TestSyncRejectsIdentityReplacedWhileWaiting(t *testing.T) {
	setSyncMaxWait(t, time.Minute)
	deps := buildDeps(t)
	cfg := deps.ServerCfg
	cfg.Certificates = append(cfg.Certificates, config.CertificateSpec{
		Name: "payroll-prod", CA: "letsencrypt", Domains: []string{"payroll.example.com"}, Subscribers: []string{"web-1"},
	})
	seedCert(t, deps, cfg, cfg.Certificates[0], "sha256:API")
	replaced := makeEnrolledClientCert(t, deps, "web-1")
	handler := NewInsecure(deps).Handler
	_, etag := syncView(t, handler, replaced)

	answered := startSync(handler, syncRequest(replaced, etag))
	assertWaiting(t, answered)
	renewed := makeClientCert(t, deps.MiniCA, "web-1")
	if err := deps.DB.Clients.StagePendingIdentity(context.Background(), "web-1", ca.Fingerprint(renewed.Certificate[0]), time.Now().Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	firstUse := httptest.NewRecorder()
	handler.ServeHTTP(firstUse, syncRequest(renewed, ""))
	if firstUse.Code != http.StatusOK {
		t.Fatalf("first use of the renewed identity: status = %d", firstUse.Code)
	}
	seedCert(t, deps, cfg, cfg.Certificates[1], "sha256:PAYROLL")
	deps.Changes.Notify()
	rec := awaitSync(t, answered)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %s; want 401", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); strings.Contains(body, "payroll-prod") || strings.Contains(body, "api-prod") {
		t.Fatalf("401 carries the view: %s", body)
	}
	if got := rec.Header().Get("ETag"); got != "" {
		t.Fatalf("401 carries the ETag of the new view: %s", got)
	}
}

func TestSyncAnswersAtShutdown(t *testing.T) {
	setSyncMaxWait(t, time.Minute)
	deps := buildDeps(t)
	shutdown := make(chan struct{})
	deps.Done = shutdown
	identity := makeEnrolledClientCert(t, deps, "web-1")
	handler := NewInsecure(deps).Handler
	_, etag := syncView(t, handler, identity)

	answered := startSync(handler, syncRequest(identity, etag))
	assertWaiting(t, answered)
	close(shutdown)
	rec := awaitSync(t, answered)
	if rec.Code != http.StatusNotModified || rec.Header().Get("ETag") != etag {
		t.Fatalf("status = %d, ETag = %s; want 304 with %s", rec.Code, rec.Header().Get("ETag"), etag)
	}
}

// TestSyncOutlivesServerTimeouts waits out a sync over real connections to a
// server whose read and write timeouts, like the 15s and 30s of production,
// end before the wait does.
func TestSyncOutlivesServerTimeouts(t *testing.T) {
	for _, tt := range []struct {
		name       string
		http2      bool
		protoMajor int
	}{
		{name: "HTTP/1.1", protoMajor: 1},
		{name: "HTTP/2", http2: true, protoMajor: 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			setSyncMaxWait(t, 3*time.Second)
			deps := buildDeps(t)
			identity := makeEnrolledClientCert(t, deps, "web-1")

			handler := NewInsecure(deps).Handler
			ctxErrs := make(chan error, 2)
			ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handler.ServeHTTP(w, r)
				ctxErrs <- r.Context().Err()
			}))
			pool := x509.NewCertPool()
			pool.AddCert(deps.MiniCA.Cert())
			ts.TLS = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool}
			ts.EnableHTTP2 = tt.http2
			ts.Config.ReadTimeout = time.Second
			ts.Config.WriteTimeout = time.Second
			ts.StartTLS()
			defer ts.Close()
			client := ts.Client()
			client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{*identity}

			first, err := client.Get(ts.URL + "/v1/sync")
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, first.Body)
			first.Body.Close()
			etag := first.Header.Get("ETag")
			if first.StatusCode != http.StatusOK || etag == "" {
				t.Fatalf("first sync: status = %d, ETag = %q", first.StatusCode, etag)
			}
			<-ctxErrs

			req, err := http.NewRequest(http.MethodGet, ts.URL+"/v1/sync", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("If-None-Match", etag)
			start := time.Now()
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("waiting sync failed after %s: %v", time.Since(start), err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			elapsed := time.Since(start)
			if resp.StatusCode != http.StatusNotModified || resp.Header.Get("ETag") != etag {
				t.Fatalf("status = %d, ETag = %s; want 304 with %s", resp.StatusCode, resp.Header.Get("ETag"), etag)
			}
			if elapsed < syncMaxWait {
				t.Fatalf("answered after %s, before waiting out %s", elapsed, syncMaxWait)
			}
			if resp.ProtoMajor != tt.protoMajor {
				t.Fatalf("protocol = %s, want %s", resp.Proto, tt.name)
			}
			if err := <-ctxErrs; err != nil {
				t.Fatalf("the waiting handler's context ended: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GET /v1/certificates/{name}/bundle
// ---------------------------------------------------------------------------

func TestGetCertBundle_Success(t *testing.T) {
	deps := buildDeps(t)
	_ = deps.DB.Certs.Upsert(context.Background(), &store.CertRecord{
		Name:            "api-prod",
		CA:              "letsencrypt",
		Domains:         []string{"api.example.com"},
		SpecFingerprint: config.CertificateSpecFingerprint(deps.ServerCfg, deps.ServerCfg.Certificates[0]),
		FullchainPEM:    "chain",
		KeyPEM:          "key",
		Fingerprint:     "sha256:AABB",
		UpdatedAt:       time.Now(),
	}, nil)

	clientCert := makeEnrolledClientCert(t, deps, "web-1")
	req := httptest.NewRequest(http.MethodGet, "/v1/certificates/api-prod/bundle", nil)
	req = simulateMTLS(req, clientCert)
	rec := httptest.NewRecorder()
	NewInsecure(deps).Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, body: %s", rec.Code, rec.Body.String())
	}
	var bundle proto.CertBundle
	_ = json.NewDecoder(rec.Body).Decode(&bundle)
	if bundle.FullchainPEM != "chain" || bundle.KeyPEM != "key" || bundle.Fingerprint != "sha256:AABB" {
		t.Errorf("bundle fields wrong: %+v", bundle)
	}
}

func TestGetCertBundleRejectsStaleMaterialAfterSpecReload(t *testing.T) {
	deps := buildDeps(t)
	next := *deps.ServerCfg
	next.Certificates = append([]config.CertificateSpec(nil), deps.ServerCfg.Certificates...)
	next.Certificates[0].Domains = []string{"api-v2.example.com"}
	deps.CurrentServer = func() *config.ServerConfig { return &next }
	_ = deps.DB.Certs.Upsert(context.Background(), &store.CertRecord{
		Name:            "api-prod",
		CA:              "letsencrypt",
		Domains:         []string{"api.example.com"},
		SpecFingerprint: config.CertificateSpecFingerprint(deps.ServerCfg, deps.ServerCfg.Certificates[0]),
		FullchainPEM:    "old-chain",
		KeyPEM:          "old-private-key",
		UpdatedAt:       time.Now(),
	}, nil)

	clientCert := makeEnrolledClientCert(t, deps, "web-1")
	req := simulateMTLS(httptest.NewRequest(http.MethodGet, "/v1/certificates/api-prod/bundle", nil), clientCert)
	rec := httptest.NewRecorder()
	NewInsecure(deps).Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "old-private-key") {
		t.Fatal("stale private key was returned")
	}
}

func TestGetCertBundleRejectsOldKeyTypeAfterReload(t *testing.T) {
	deps := buildDeps(t)
	oldCfg := *deps.ServerCfg
	oldCfg.Certificates = append([]config.CertificateSpec(nil), deps.ServerCfg.Certificates...)
	oldCfg.Certificates[0].KeyType = "ec256"
	next := oldCfg
	next.Certificates = append([]config.CertificateSpec(nil), oldCfg.Certificates...)
	next.Certificates[0].KeyType = "rsa2048"
	deps.CurrentServer = func() *config.ServerConfig { return &next }
	_ = deps.DB.Certs.Upsert(context.Background(), &store.CertRecord{
		Name: "api-prod", CA: "letsencrypt", Domains: []string{"api.example.com"},
		SpecFingerprint: config.CertificateSpecFingerprint(&oldCfg, oldCfg.Certificates[0]),
		FullchainPEM:    "old-chain", KeyPEM: "old-private-key", UpdatedAt: time.Now(),
	}, nil)

	clientCert := makeEnrolledClientCert(t, deps, "web-1")
	req := simulateMTLS(httptest.NewRequest(http.MethodGet, "/v1/certificates/api-prod/bundle", nil), clientCert)
	rec := httptest.NewRecorder()
	NewInsecure(deps).Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestGetCertBundle_Unauthorized(t *testing.T) {
	deps := buildDeps(t)
	// web-2 is not subscribed.
	clientCert := makeEnrolledClientCert(t, deps, "web-2")
	req := httptest.NewRequest(http.MethodGet, "/v1/certificates/api-prod/bundle", nil)
	req = simulateMTLS(req, clientCert)
	rec := httptest.NewRecorder()
	NewInsecure(deps).Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// POST /v1/heartbeat
// ---------------------------------------------------------------------------

func TestHeartbeat_Success(t *testing.T) {
	deps := buildDeps(t)
	clientCert := makeEnrolledClientCert(t, deps, "web-1")

	body, _ := json.Marshal(proto.HeartbeatRequest{Fingerprint: "sha256:NEWF"})
	req := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = simulateMTLS(req, clientCert)
	rec := httptest.NewRecorder()
	NewInsecure(deps).Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
	cl, err := deps.DB.Clients.Get(context.Background(), "web-1", nil)
	if err != nil {
		t.Fatalf("client not found after heartbeat: %v", err)
	}
	if cl.Fingerprint != ca.Fingerprint(clientCert.Certificate[0]) {
		t.Errorf("identity fingerprint was overwritten: %s", cl.Fingerprint)
	}
	if cl.LastSeen.IsZero() {
		t.Error("last seen was not updated")
	}
}

func TestHeartbeatDoesNotRecreateClientRemovedDuringRequest(t *testing.T) {
	deps, other := buildFileDeps(t)
	identity := makeEnrolledClientCert(t, deps, "web-1")
	ctx := context.Background()

	tx, err := other.BeginTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := other.Clients.Delete(ctx, "web-1", tx); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(proto.HeartbeatRequest{})
	req := simulateMTLS(httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewReader(body)), identity)
	rec := requestDuringWrite(t, NewInsecure(deps).Handler, req, tx)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if _, err := deps.DB.Clients.Get(ctx, "web-1", nil); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("heartbeat recreated a removed client: Get error = %v", err)
	}
}

func TestHeartbeatKeepsIdentityStagedDuringRequest(t *testing.T) {
	deps, other := buildFileDeps(t)
	identity := makeEnrolledClientCert(t, deps, "web-1")
	ctx := context.Background()

	staged, err := deps.DB.Clients.Get(ctx, "web-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	staged.PendingFingerprint = "sha256:renewed"
	staged.PendingNotAfter = time.Now().UTC().Add(90 * 24 * time.Hour)
	tx, err := other.BeginTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := other.Clients.Upsert(ctx, staged, tx); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(proto.HeartbeatRequest{})
	req := simulateMTLS(httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewReader(body)), identity)
	rec := requestDuringWrite(t, NewInsecure(deps).Handler, req, tx)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	got, err := deps.DB.Clients.Get(ctx, "web-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.PendingFingerprint != "sha256:renewed" {
		t.Fatalf("heartbeat discarded the staged identity: %+v", got)
	}
	if got.LastSeen.IsZero() {
		t.Error("last seen was not updated")
	}
}

func TestRemovedClientCannotUseMTLSAPI(t *testing.T) {
	deps := buildDeps(t)
	clientCert := makeEnrolledClientCert(t, deps, "web-1")
	if err := deps.DB.Clients.Delete(context.Background(), "web-1", nil); err != nil {
		t.Fatalf("delete client: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/sync", nil)
	req = simulateMTLS(req, clientCert)
	rec := httptest.NewRecorder()
	NewInsecure(deps).Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("removed client: expected 401, got %d", rec.Code)
	}

	body, _ := json.Marshal(proto.HeartbeatRequest{})
	req = httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewReader(body))
	req = simulateMTLS(req, clientCert)
	rec = httptest.NewRecorder()
	NewInsecure(deps).Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("removed client heartbeat: expected 401, got %d", rec.Code)
	}
	if _, err := deps.DB.Clients.Get(context.Background(), "web-1", nil); err == nil {
		t.Fatal("heartbeat recreated a removed client")
	}
}

func TestHeartbeat_NoMTLS(t *testing.T) {
	deps := buildDeps(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/heartbeat", nil)
	rec := httptest.NewRecorder()
	NewInsecure(deps).Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// mTLS client check: identity and last_seen
// ---------------------------------------------------------------------------

// buildFileDeps is buildDeps on a database file, plus a second handle to the
// same file that tests use as a concurrent writer (client removal, identity
// renewal). busy_timeout makes the API's writes wait for that writer's
// transaction instead of failing with SQLITE_BUSY.
func buildFileDeps(t *testing.T) (Deps, *store.DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sigils.db")
	db, err := store.Open(path + "?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	other, err := store.Open(path)
	if err != nil {
		t.Fatalf("open second db handle: %v", err)
	}
	t.Cleanup(func() { _ = other.Close() })

	deps := buildDeps(t)
	deps.DB = db
	deps.EnrollServer = enroll.NewServer(db.Tokens, db.Clients, deps.MiniCA)
	return deps, other
}

// requestDuringWrite has handler serve req while writeTx, an uncommitted
// transaction on another handle, holds the database write lock. The request's
// reads see the state before writeTx, so its lookup of the client passes, and
// its writes wait until writeTx commits. The commit is delayed so the request
// has normally finished its reads by then, which places the concurrent change
// between the request's lookup and its write. The outcome the tests assert
// must hold for every interleaving; the delay only makes a regression, such as
// a read-modify-write of the client record, observable.
func requestDuringWrite(t *testing.T, handler http.Handler, req *http.Request, writeTx *sql.Tx) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handler.ServeHTTP(rec, req)
	}()
	time.Sleep(200 * time.Millisecond)
	commitErr := writeTx.Commit()
	<-done
	if commitErr != nil {
		t.Fatalf("commit concurrent write: %v", commitErr)
	}
	return rec
}

func TestAuthenticatedRequestsRecordLastSeenAtMostOncePerInterval(t *testing.T) {
	deps := buildDeps(t)
	identity := makeEnrolledClientCert(t, deps, "web-1")
	ctx := context.Background()
	handler := NewInsecure(deps).Handler
	request := func() {
		t.Helper()
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, syncRequest(identity, ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	}
	lastSeen := func() time.Time {
		t.Helper()
		rec, err := deps.DB.Clients.Get(ctx, "web-1", nil)
		if err != nil {
			t.Fatal(err)
		}
		return rec.LastSeen
	}
	// A value that no request writes, so a write since shows as a change.
	sentinel := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	setSentinel := func() {
		t.Helper()
		rec, err := deps.DB.Clients.Get(ctx, "web-1", nil)
		if err != nil {
			t.Fatal(err)
		}
		rec.LastSeen = sentinel
		if err := deps.DB.Clients.Upsert(ctx, rec, nil); err != nil {
			t.Fatal(err)
		}
	}

	request()
	if lastSeen().IsZero() {
		t.Fatal("the first request did not record last_seen")
	}

	setSentinel()
	request()
	if got := lastSeen(); !got.Equal(sentinel) {
		t.Fatalf("a second request within the interval wrote last_seen %s", got)
	}

	previous := lastSeenInterval
	lastSeenInterval = 10 * time.Millisecond
	t.Cleanup(func() { lastSeenInterval = previous })
	time.Sleep(20 * time.Millisecond)
	request()
	if got := lastSeen(); got.Equal(sentinel) {
		t.Fatal("a request after the interval did not write last_seen")
	}
}

// last_seen only records that an authenticated client was here: a request
// whose write of it fails is served all the same, and the write is tried
// again only after the interval.
func TestAuthenticatedRequestIsServedWhenLastSeenCannotBeWritten(t *testing.T) {
	deps, other := buildFileDeps(t)
	identity := makeEnrolledClientCert(t, deps, "web-1")
	ctx := context.Background()
	// The API writes through the handle without busy_timeout, so its write
	// fails at once while the other handle holds the write lock.
	locker := deps.DB
	deps.DB = other
	handler := NewInsecure(deps).Handler
	request := func() {
		t.Helper()
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, syncRequest(identity, ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	}
	assertNotSeen := func() {
		t.Helper()
		got, err := deps.DB.Clients.Get(ctx, "web-1", nil)
		if err != nil {
			t.Fatal(err)
		}
		if !got.LastSeen.IsZero() {
			t.Fatalf("last_seen = %s, want it not written", got.LastSeen)
		}
	}

	record, err := locker.Clients.Get(ctx, "web-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := locker.BeginTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := locker.Clients.Upsert(ctx, record, tx); err != nil {
		t.Fatal(err)
	}
	request()
	assertNotSeen()
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}

	request()
	assertNotSeen()
}

func TestAuthenticatedRequestDoesNotRecreateClientRemovedDuringRequest(t *testing.T) {
	deps, other := buildFileDeps(t)
	identity := makeEnrolledClientCert(t, deps, "web-1")
	ctx := context.Background()

	tx, err := other.BeginTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := other.Clients.Delete(ctx, "web-1", tx); err != nil {
		t.Fatal(err)
	}

	rec := requestDuringWrite(t, NewInsecure(deps).Handler, syncRequest(identity, ""), tx)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if _, err := deps.DB.Clients.Get(ctx, "web-1", nil); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("recording last_seen recreated a removed client: Get error = %v", err)
	}
}

func TestAuthenticatedRequestKeepsIdentityStagedDuringRequest(t *testing.T) {
	deps, other := buildFileDeps(t)
	identity := makeEnrolledClientCert(t, deps, "web-1")
	ctx := context.Background()

	staged, err := deps.DB.Clients.Get(ctx, "web-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	staged.PendingFingerprint = "sha256:renewed"
	staged.PendingNotAfter = time.Now().UTC().Add(90 * 24 * time.Hour)
	tx, err := other.BeginTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := other.Clients.Upsert(ctx, staged, tx); err != nil {
		t.Fatal(err)
	}

	rec := requestDuringWrite(t, NewInsecure(deps).Handler, syncRequest(identity, ""), tx)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	got, err := deps.DB.Clients.Get(ctx, "web-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.PendingFingerprint != "sha256:renewed" {
		t.Fatalf("recording last_seen discarded the staged identity: %+v", got)
	}
	if got.LastSeen.IsZero() {
		t.Error("last seen was not updated")
	}
}

// The first uses of a renewed identity can arrive together: both see it
// pending, and the one whose promotion comes second finds nothing to promote.
func TestAuthenticatedRequestAcceptsIdentityPromotedDuringRequest(t *testing.T) {
	deps, other := buildFileDeps(t)
	makeEnrolledClientCert(t, deps, "web-1")
	renewed := makeClientCert(t, deps.MiniCA, "web-1")
	renewedFingerprint := ca.Fingerprint(renewed.Certificate[0])
	ctx := context.Background()
	if err := deps.DB.Clients.StagePendingIdentity(ctx, "web-1", renewedFingerprint, time.Now().Add(90*24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	promoted, err := deps.DB.Clients.Get(ctx, "web-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	promoted.Fingerprint = renewedFingerprint
	promoted.PendingFingerprint = ""
	promoted.PendingNotAfter = time.Time{}
	tx, err := other.BeginTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := other.Clients.Upsert(ctx, promoted, tx); err != nil {
		t.Fatal(err)
	}

	rec := requestDuringWrite(t, NewInsecure(deps).Handler, syncRequest(renewed, ""), tx)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	got, err := deps.DB.Clients.Get(ctx, "web-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != renewedFingerprint || got.LastSeen.IsZero() {
		t.Fatalf("unexpected client after the request: %+v", got)
	}
}

// Clients that share a name, such as clones of one machine, can renew in
// turn: a newer renewal replaces the pending identity between the lookup and
// the promotion. The read after the failed promotion must refuse the replaced
// identity rather than accept any client it finds.
func TestAuthenticatedRequestRejectsPendingIdentityReplacedDuringRequest(t *testing.T) {
	deps, other := buildFileDeps(t)
	enrolled := makeEnrolledClientCert(t, deps, "web-1")
	replaced := makeClientCert(t, deps.MiniCA, "web-1")
	newer := makeClientCert(t, deps.MiniCA, "web-1")
	ctx := context.Background()
	if err := deps.DB.Clients.StagePendingIdentity(ctx, "web-1", ca.Fingerprint(replaced.Certificate[0]), time.Now().Add(90*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	restaged, err := deps.DB.Clients.Get(ctx, "web-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	restaged.PendingFingerprint = ca.Fingerprint(newer.Certificate[0])

	// A request of the active identity claims this interval's last_seen
	// write, so no MarkSeen runs for the request under test: its WHERE on the
	// fingerprint would refuse the replaced identity too and hide a missing
	// check. It must come before the transaction, whose write lock it would
	// otherwise wait for.
	handler := NewInsecure(deps).Handler
	active := httptest.NewRecorder()
	handler.ServeHTTP(active, syncRequest(enrolled, ""))
	if active.Code != http.StatusOK {
		t.Fatalf("active identity: status = %d", active.Code)
	}

	tx, err := other.BeginTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := other.Clients.Upsert(ctx, restaged, tx); err != nil {
		t.Fatal(err)
	}

	rec := requestDuringWrite(t, handler, syncRequest(replaced, ""), tx)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	got, err := deps.DB.Clients.Get(ctx, "web-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != ca.Fingerprint(enrolled.Certificate[0]) || got.PendingFingerprint != ca.Fingerprint(newer.Certificate[0]) {
		t.Fatalf("unexpected client after the request: %+v", got)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
