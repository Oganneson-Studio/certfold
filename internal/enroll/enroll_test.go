package enroll

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/ca"
	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/store"
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

// newCSR returns the CSR that GenerateKeyAndCSR makes for name, parsed as
// the API parses it before SignClientCert.
func newCSR(t *testing.T, name string) *x509.CertificateRequest {
	t.Helper()
	kc, err := GenerateKeyAndCSR(name)
	if err != nil {
		t.Fatalf("GenerateKeyAndCSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(kc.CSRDER)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	return csr
}

// ---------------------------------------------------------------------------
// Server-side
// ---------------------------------------------------------------------------

func TestCreateAndVerify(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	miniCA := mustBootstrapCA(t)
	srv := NewServer(db, miniCA)

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
	srv := NewServer(db, miniCA)

	tokenStr, _ := srv.Create(ctx, "https://sigil.example.com", "web-1", time.Hour)

	// Decode, tamper secret, re-encode.
	payload, _ := DecodeToken(tokenStr)
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
	srv := NewServer(db, mustBootstrapCA(t))
	tokenStr, err := srv.Create(ctx, "https://sigil.example.com", "web-1", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	for _, mutate := range []struct {
		name string
		fn   func(*Token)
	}{
		{name: "server URL", fn: func(p *Token) { p.ServerURL = "https://attacker.example" }},
		{name: "client name", fn: func(p *Token) { p.Name = "attacker" }},
		{name: "CA certificate", fn: func(p *Token) { p.CACert = "attacker-ca" }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			payload, err := DecodeToken(tokenStr)
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
	srv := NewServer(db, miniCA)

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
	srv := NewServer(db, miniCA)

	payload := Token{
		ServerURL: "https://sigil.example.com",
		Name:      "web-1",
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
	srv := NewServer(db, miniCA)

	tokenStr, err := srv.Create(ctx, "https://sigil.example.com", "web-1", time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	name, tokenID, err := srv.Verify(ctx, tokenStr)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	certDER, err := srv.SignClientCert(ctx, newCSR(t, name), name, tokenID)
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
	srv := NewServer(db, miniCA)

	tokenStr, _ := srv.Create(ctx, "https://sigil.example.com", "web-1", time.Hour)
	name, tokenID, _ := srv.Verify(ctx, tokenStr)

	_, err := srv.SignClientCert(ctx, newCSR(t, name), name, tokenID)
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
	srv := NewServer(db, miniCA)

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
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, call := range []struct {
		csr     *x509.CertificateRequest
		name    string
		tokenID string
	}{
		{newCSR(t, name1), name1, tokenID1},
		{newCSR(t, name2), name2, tokenID2},
	} {
		wg.Add(1)
		go func(call struct {
			csr     *x509.CertificateRequest
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
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrTokenUsed):
			failed++
		default:
			t.Errorf("concurrent consumption: error = %v, want ErrTokenUsed", err)
		}
	}
	if succeeded != 1 || failed != 1 {
		t.Fatalf("concurrent consumption: %d succeeded, %d failed; want 1 and 1", succeeded, failed)
	}
}

// TestVerifySaysWhyOnlyToTheTokenHolder checks that a token which no longer
// enrolls is refused for its reason, used or expired, but only when its
// secret checks out: without the secret, a token ID says nothing.
func TestVerifySaysWhyOnlyToTheTokenHolder(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	srv := NewServer(db, mustBootstrapCA(t))
	used, err := srv.Create(ctx, "https://sigil.example.com", "web-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	name, tokenID, err := srv.Verify(ctx, used)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.SignClientCert(ctx, newCSR(t, name), name, tokenID); err != nil {
		t.Fatal(err)
	}
	expired, err := srv.Create(ctx, "https://sigil.example.com", "web-2", -time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	withoutSecret := func(tokenStr string) string {
		payload, err := DecodeToken(tokenStr)
		if err != nil {
			t.Fatal(err)
		}
		payload.Secret = strings.Repeat("a", 64)
		return encodeTestToken(t, *payload)
	}

	for _, tt := range []struct {
		name  string
		token string
		want  error
	}{
		{"used", used, ErrTokenUsed},
		{"expired", expired, ErrTokenExpired},
		{"used, without the secret", withoutSecret(used), ErrInvalidToken},
		{"expired, without the secret", withoutSecret(expired), ErrInvalidToken},
		{"not a token", "not-a-token", ErrInvalidToken},
	} {
		if _, _, err := srv.Verify(ctx, tt.token); !errors.Is(err, tt.want) {
			t.Errorf("Verify of a token %s: error = %v, want %v", tt.name, err, tt.want)
		}
	}
}

// TestPostEnrollSaysWhyTheServerRefused checks that the reason the server
// gives reaches the error that sigilc prints.
func TestPostEnrollSaysWhyTheServerRefused(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "enrollment token was already used", http.StatusUnauthorized)
	}))
	defer ts.Close()

	token := encodeTestToken(t, Token{ServerURL: ts.URL, Name: "web-1", CACert: testServerCertPEM(t, ts)})
	kc, err := GenerateKeyAndCSR("web-1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = postEnroll(t, token, kc.CSRDER)
	if want := "server returned 401: enrollment token was already used"; err == nil || err.Error() != want {
		t.Fatalf("PostEnroll error = %v, want %q", err, want)
	}
}

// TestSignClientCertKeepsTokenWhenClientIsNotRecorded checks that the token
// is consumed only together with the record of its client: an enrollment
// that fails to record the client leaves the token for another attempt.
func TestSignClientCertKeepsTokenWhenClientIsNotRecorded(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sigils.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv := NewServer(db, mustBootstrapCA(t))
	tokenStr, err := srv.Create(ctx, "https://sigil.example.com", "web-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	name, tokenID, err := srv.Verify(ctx, tokenStr)
	if err != nil {
		t.Fatal(err)
	}

	// Make every write of a client fail.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`CREATE TRIGGER refuse_clients BEFORE INSERT ON clients BEGIN SELECT RAISE(ABORT, 'refused'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.SignClientCert(ctx, newCSR(t, name), name, tokenID); err == nil {
		t.Fatal("SignClientCert succeeded without recording the client")
	}
	rec, err := db.Tokens.Get(ctx, tokenID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !rec.UsedAt.IsZero() {
		t.Fatalf("the token was used up by an enrollment that failed: used at %s", rec.UsedAt)
	}

	if _, err := raw.Exec(`DROP TRIGGER refuse_clients`); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.SignClientCert(ctx, newCSR(t, name), name, tokenID); err != nil {
		t.Fatalf("enrollment with the token left unused: %v", err)
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

func encodeTestToken(t *testing.T, payload Token) string {
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

	// The first save adds the identity, the second, of a renewal, replaces it.
	if err := SaveIdentity(cfgPath, "old-ca", "old-client", "old-key"); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
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
	if strings.Contains(s, "old-") || strings.Count(s, "identity:") != 1 {
		t.Errorf("the second save did not replace the identity of the first:\n%s", s)
	}
}

// clientYAMLByHand is a client.yaml as an operator writes it: comments, keys
// in the order they chose, a mode in octal and a PKCS#12 password that YAML
// would read as a number if it were not decoded into a string field.
const clientYAMLByHand = "# managed by ops: do not reorder\n" +
	"client:\n" +
	"  server_url: https://sigil.example.com\n" +
	"  name: web-1\n" +
	"certificates:\n" +
	"  api:\n" +
	"    outputs:\n" +
	"      - format: pkcs12\n" +
	"        path: /etc/ssl/api.p12\n" +
	"        password: 0123\n" +
	"        mode: 0640 # read by the web server group\n"

// TestSaveIdentityKeepsTheRestOfClientYAML covers `sigilc enroll` on a host
// whose client.yaml the operator wrote, and the identity renewal of the
// daemon, which saves through the same function: the comments, the order and
// the text of the operator's file must survive, as they do when sigils edits
// server.yaml.
func TestSaveIdentityKeepsTheRestOfClientYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.yaml")
	if err := os.WriteFile(path, []byte(clientYAMLByHand), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SaveIdentity(path, "CA", "CERT", "KEY"); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# managed by ops: do not reorder", "# read by the web server group", "mode: 0640", "password: 0123"} {
		if !strings.Contains(string(saved), want) {
			t.Errorf("client.yaml lost %q:\n%s", want, saved)
		}
	}
	if strings.Index(string(saved), "server_url") > strings.Index(string(saved), "name:") {
		t.Errorf("client.yaml keys were reordered:\n%s", saved)
	}
}

// TestSaveIdentityKeepsValuesAsSigilcReadsThem covers the same save for a
// value that sigilc reads as a string but a map[string]any reads as a number:
// the unquoted password 0123 is octal 83 to YAML, so a round trip through a
// map writes 83, and the next load encrypts the PKCS#12 output with another
// password than the one its consumers were given.
func TestSaveIdentityKeepsValuesAsSigilcReadsThem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.yaml")
	if err := os.WriteFile(path, []byte(clientYAMLByHand), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := config.ParseClient([]byte(clientYAMLByHand))
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveIdentity(path, "", "", ""); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	after, err := config.ParseClient(saved)
	if err != nil {
		t.Fatalf("saved client.yaml no longer loads: %v\n%s", err, saved)
	}
	want := before.Certificates["api"].Outputs[0].Password
	if got := after.Certificates["api"].Outputs[0].Password; got != want {
		t.Fatalf("PKCS#12 password changed from %q to %q by saving the identity:\n%s", want, got, saved)
	}
}
