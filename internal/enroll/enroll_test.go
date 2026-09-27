package enroll

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/ca"
	"github.com/Oganneson-Studio/sigil/internal/store"
	"github.com/Oganneson-Studio/sigil/pkg/proto"
)

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

// ---------------------------------------------------------------------------
// Server-side
// ---------------------------------------------------------------------------

func TestCreateAndVerify(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	miniCA := mustBootstrapCA(t)
	srv := NewServer(db.Tokens, db.Clients, miniCA)

	tokenStr, err := srv.Create(ctx, "https://sigil.example.com", "web-1", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("empty token string")
	}
	name, tokenID, err := srv.Verify(ctx, tokenStr)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if name != "web-1" {
		t.Errorf("name: got %q, want %q", name, "web-1")
	}
	if tokenID == "" {
		t.Error("empty tokenID from Verify")
	}
}

func TestVerify_TamperedSecret(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	miniCA := mustBootstrapCA(t)
	srv := NewServer(db.Tokens, db.Clients, miniCA)

	tokenStr, _ := srv.Create(ctx, "https://sigil.example.com", "web-1", time.Hour)

	// Decode, tamper secret, re-encode.
	payload, _ := decodeToken(tokenStr)
	payload.Secret = strings.Repeat("a", 64)
	tampered, _ := json.Marshal(payload)
	tamperedStr := base64.RawURLEncoding.EncodeToString(tampered)

	_, _, err := srv.Verify(ctx, tamperedStr)
	if err == nil {
		t.Error("expected error for tampered secret, got nil")
	}
}

func TestVerify_TamperedTrustData(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	srv := NewServer(db.Tokens, db.Clients, mustBootstrapCA(t))
	tokenStr, err := srv.Create(ctx, "https://sigil.example.com", "web-1", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	for _, mutate := range []struct {
		name string
		fn   func(*tokenPayload)
	}{
		{name: "server URL", fn: func(p *tokenPayload) { p.ServerURL = "https://attacker.example" }},
		{name: "client name", fn: func(p *tokenPayload) { p.Name = "attacker" }},
		{name: "CA certificate", fn: func(p *tokenPayload) { p.CACert = "attacker-ca" }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			payload, err := decodeToken(tokenStr)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			mutate.fn(payload)
			tampered := encodeTestToken(t, *payload)
			if _, _, err := srv.Verify(ctx, tampered); err == nil {
				t.Fatal("expected tampered token to be rejected")
			}
		})
	}
}

func TestVerify_ExpiredToken(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	miniCA := mustBootstrapCA(t)
	srv := NewServer(db.Tokens, db.Clients, miniCA)

	tokenStr, err := srv.Create(ctx, "https://sigil.example.com", "web-1", -time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, _, err = srv.Verify(ctx, tokenStr)
	if err == nil {
		t.Error("expected error for expired token")
	}
}

func TestVerify_UnknownToken(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	miniCA := mustBootstrapCA(t)
	srv := NewServer(db.Tokens, db.Clients, miniCA)

	payload := tokenPayload{
		ServerURL: "https://sigil.example.com",
		TokenID:   "deadbeefdeadbeefdeadbeefdeadbeef",
		Secret:    strings.Repeat("a", 64),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	raw, _ := json.Marshal(payload)
	tokenStr := base64.RawURLEncoding.EncodeToString(raw)

	_, _, err := srv.Verify(ctx, tokenStr)
	if err == nil {
		t.Error("expected error for unknown token, got nil")
	}
}

func TestSignClientCert_E2E(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	miniCA := mustBootstrapCA(t)
	srv := NewServer(db.Tokens, db.Clients, miniCA)

	tokenStr, err := srv.Create(ctx, "https://sigil.example.com", "web-1", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	name, tokenID, err := srv.Verify(ctx, tokenStr)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	kc, err := GenerateKeyAndCSR(name)
	if err != nil {
		t.Fatalf("GenerateKeyAndCSR: %v", err)
	}

	certDER, err := srv.SignClientCert(ctx, kc.CSRDER, name, tokenID)
	if err != nil {
		t.Fatalf("SignClientCert: %v", err)
	}

	// Token must be marked used.
	rec, err := db.Tokens.Get(ctx, tokenID, nil)
	if err != nil {
		t.Fatalf("get token: %v", err)
	}
	if rec.UsedAt.IsZero() {
		t.Error("token UsedAt should be set after SignClientCert")
	}

	// Client must be recorded.
	cl, err := db.Clients.Get(ctx, "web-1", nil)
	if err != nil {
		t.Fatalf("get client: %v", err)
	}
	if cl.Name != "web-1" {
		t.Errorf("client name: %q", cl.Name)
	}

	// Cert must be verifiable against the CA.
	caPool := x509.NewCertPool()
	caPool.AddCert(miniCA.Cert())
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	opts := x509.VerifyOptions{Roots: caPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if _, err := cert.Verify(opts); err != nil {
		t.Errorf("cert not valid against CA: %v", err)
	}
}

func TestTokenReplay(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	miniCA := mustBootstrapCA(t)
	srv := NewServer(db.Tokens, db.Clients, miniCA)

	tokenStr, _ := srv.Create(ctx, "https://sigil.example.com", "web-1", time.Hour)
	name, tokenID, _ := srv.Verify(ctx, tokenStr)

	kc, _ := GenerateKeyAndCSR(name)
	_, err := srv.SignClientCert(ctx, kc.CSRDER, name, tokenID)
	if err != nil {
		t.Fatalf("first sign: %v", err)
	}

	// Second Verify must fail because UsedAt is set.
	_, _, err = srv.Verify(ctx, tokenStr)
	if err == nil {
		t.Error("expected error on token replay, got nil")
	}
}

func TestTokenConcurrentConsumption(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	miniCA := mustBootstrapCA(t)
	srv := NewServer(db.Tokens, db.Clients, miniCA)

	tokenStr, err := srv.Create(ctx, "https://sigil.example.com", "web-1", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	name1, tokenID1, err := srv.Verify(ctx, tokenStr)
	if err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	name2, tokenID2, err := srv.Verify(ctx, tokenStr)
	if err != nil {
		t.Fatalf("second Verify: %v", err)
	}
	kc1, _ := GenerateKeyAndCSR(name1)
	kc2, _ := GenerateKeyAndCSR(name2)

	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, call := range []struct {
		csr     []byte
		name    string
		tokenID string
	}{
		{kc1.CSRDER, name1, tokenID1},
		{kc2.CSRDER, name2, tokenID2},
	} {
		wg.Add(1)
		go func(call struct {
			csr     []byte
			name    string
			tokenID string
		}) {
			defer wg.Done()
			<-start
			_, err := srv.SignClientCert(ctx, call.csr, call.name, call.tokenID)
			results <- err
		}(call)
	}
	close(start)
	wg.Wait()
	close(results)

	succeeded := 0
	failed := 0
	for err := range results {
		if err == nil {
			succeeded++
		} else {
			failed++
		}
	}
	if succeeded != 1 || failed != 1 {
		t.Fatalf("concurrent consumption: %d succeeded, %d failed; want 1 and 1", succeeded, failed)
	}
}

// ---------------------------------------------------------------------------
// Client-side
// ---------------------------------------------------------------------------

func TestGenerateKeyAndCSR(t *testing.T) {
	kc, err := GenerateKeyAndCSR("web-1")
	if err != nil {
		t.Fatalf("GenerateKeyAndCSR: %v", err)
	}
	block, _ := pem.Decode(kc.KeyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Error("KeyPEM is not a PRIVATE KEY PEM block")
	}
	csr, err := x509.ParseCertificateRequest(kc.CSRDER)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	if csr.Subject.CommonName != "web-1" {
		t.Errorf("CN: got %q, want %q", csr.Subject.CommonName, "web-1")
	}
}

func TestPostEnroll(t *testing.T) {
	resp := proto.EnrollResponse{CACert: "ca-pem", ClientCert: "client-pem"}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/enroll" || r.Method != http.MethodPost {
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	token := encodeTestToken(t, tokenPayload{ServerURL: ts.URL, CACert: testServerCertPEM(t, ts)})
	kc, _ := GenerateKeyAndCSR("web-1")
	got, err := PostEnroll(ts.URL, token, kc.CSRDER)
	if err != nil {
		t.Fatalf("PostEnroll: %v", err)
	}
	if got.CACert != "ca-pem" || got.ClientCert != "client-pem" {
		t.Errorf("unexpected response: %+v", got)
	}
}

// TestPostEnroll_PinnedCA verifies that enrollment succeeds against a
// self-signed server only when its certificate is pinned in the token.
func TestPostEnroll_PinnedCA(t *testing.T) {
	resp := proto.EnrollResponse{CACert: "ca-pem-pinned", ClientCert: "client-pem-pinned"}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/enroll" || r.Method != http.MethodPost {
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	token := encodeTestToken(t, tokenPayload{ServerURL: ts.URL, CACert: testServerCertPEM(t, ts)})
	kc, _ := GenerateKeyAndCSR("web-1")
	got, err := PostEnroll(ts.URL, token, kc.CSRDER)
	if err != nil {
		t.Fatalf("PostEnroll (pinned CA): %v", err)
	}
	if got.CACert != "ca-pem-pinned" || got.ClientCert != "client-pem-pinned" {
		t.Errorf("unexpected response: %+v", got)
	}
}

func TestPostEnroll_RejectsUnpinnedServer(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	other := httptest.NewTLSServer(http.NotFoundHandler())
	defer other.Close()

	token := encodeTestToken(t, tokenPayload{ServerURL: ts.URL, CACert: testServerCertPEM(t, other)})
	kc, _ := GenerateKeyAndCSR("web-1")
	if _, err := PostEnroll(ts.URL, token, kc.CSRDER); err == nil {
		t.Fatal("expected enrollment to reject a server not signed by the token CA")
	}
}

func encodeTestToken(t *testing.T, payload tokenPayload) string {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal token: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func testServerCertPEM(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	cert := ts.Certificate()
	if cert == nil {
		t.Fatal("test server has no certificate")
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

func TestSaveIdentity(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "client.yaml")
	initial := "client:\n  name: web-1\n  server_url: https://sigil.example.com\n"
	if err := os.WriteFile(cfgPath, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := SaveIdentity(cfgPath, "ca-pem", "client-pem", "key-pem"); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	out, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{"ca-pem", "client-pem", "key-pem", "web-1"} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q; got:\n%s", want, s)
		}
	}
}
