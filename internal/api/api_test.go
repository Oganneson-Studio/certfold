package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
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
	oldReq := simulateMTLS(httptest.NewRequest(http.MethodGet, "/v1/certificates", nil), oldIdentity)
	oldRec := httptest.NewRecorder()
	NewInsecure(deps).Handler.ServeHTTP(oldRec, oldReq)
	if oldRec.Code != http.StatusOK {
		t.Fatalf("old identity rejected before promotion: %d", oldRec.Code)
	}

	// First use of the new identity promotes it atomically.
	newReq := simulateMTLS(httptest.NewRequest(http.MethodGet, "/v1/certificates", nil), &newIdentity)
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

	revokedReq := simulateMTLS(httptest.NewRequest(http.MethodGet, "/v1/certificates", nil), oldIdentity)
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
	if bundle.FullchainPEM != "chain" || bundle.KeyPEM != "key" {
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

// heartbeatDuringWrite sends a heartbeat for identity while writeTx, an
// uncommitted transaction on another handle, holds the database write lock.
// The request's reads see the state before writeTx, so authentication passes,
// and its write waits until writeTx commits. The commit is delayed so the
// request has normally finished its reads by then, which places the concurrent
// change between the request's lookup and its write. The outcome the tests
// assert must hold for every interleaving; the delay only makes a regression
// to a read-modify-write heartbeat observable.
func heartbeatDuringWrite(t *testing.T, deps Deps, identity *tls.Certificate, writeTx *sql.Tx) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(proto.HeartbeatRequest{})
	req := simulateMTLS(httptest.NewRequest(http.MethodPost, "/v1/heartbeat", bytes.NewReader(body)), identity)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		NewInsecure(deps).Handler.ServeHTTP(rec, req)
	}()
	time.Sleep(200 * time.Millisecond)
	commitErr := writeTx.Commit()
	<-done
	if commitErr != nil {
		t.Fatalf("commit concurrent write: %v", commitErr)
	}
	return rec
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

	rec := heartbeatDuringWrite(t, deps, identity, tx)
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

	rec := heartbeatDuringWrite(t, deps, identity, tx)
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

	req := httptest.NewRequest(http.MethodGet, "/v1/certificates", nil)
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
// helpers
// ---------------------------------------------------------------------------

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
