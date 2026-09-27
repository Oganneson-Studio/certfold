package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/registration"
	"github.com/miekg/dns"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

// ---------------------------------------------------------------------------
// SetDNSResolvers
// ---------------------------------------------------------------------------

// TestSetDNSResolvers checks against a local DNS server that lego's DNS-01
// lookups use the resolvers SetDNSResolvers sets. It relies on a detail of
// lego v4.35.2, so it must pass again after every lego upgrade.
//
// SetDNSResolvers changes lego's process-wide resolvers and nothing can
// restore them, so the check runs in a child process.
func TestSetDNSResolvers(t *testing.T) {
	const childEnv = "SIGIL_TEST_SET_DNS_RESOLVERS"
	if os.Getenv(childEnv) == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestSetDNSResolvers$", "-test.v", "-test.timeout=1m")
		cmd.Env = append(os.Environ(), childEnv+"=1")
		out, err := cmd.CombinedOutput()
		// Without the PASS line the child may have run no test at all.
		if err != nil || !strings.Contains(string(out), "--- PASS: TestSetDNSResolvers") {
			t.Fatalf("child process: %v\n%s", err, out)
		}
		return
	}

	const zone = "zone.sigil.test."
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	server := &dns.Server{
		PacketConn:        conn,
		NotifyStartedFunc: func() { close(started) },
		// Answer the SOA query for zone and nothing else.
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			if q := r.Question[0]; q.Qtype == dns.TypeSOA && q.Name == zone {
				m.Answer = append(m.Answer, &dns.SOA{
					Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
					Ns:      "ns1." + zone,
					Mbox:    "hostmaster." + zone,
					Serial:  1,
					Refresh: 60,
					Retry:   60,
					Expire:  60,
					Minttl:  60,
				})
			} else {
				m.Rcode = dns.RcodeNameError
			}
			_ = w.WriteMsg(m)
		}),
	}
	served := make(chan error, 1)
	go func() { served <- server.ActivateAndServe() }()
	select {
	case <-started:
	case err := <-served:
		t.Fatalf("DNS server: %v", err)
	}
	defer server.Shutdown()

	SetDNSResolvers([]string{conn.LocalAddr().String()})
	// An empty list keeps the resolvers already set.
	SetDNSResolvers(nil)

	got, err := dns01.FindZoneByFqdn("_acme-challenge.www." + zone)
	if err != nil {
		t.Fatalf("FindZoneByFqdn: %v", err)
	}
	if got != zone {
		t.Fatalf("FindZoneByFqdn = %q, want %q", got, zone)
	}
}

// ---------------------------------------------------------------------------
// specKeyType mapping
// ---------------------------------------------------------------------------

func TestSpecKeyType(t *testing.T) {
	tests := []struct {
		kt   string
		want certcrypto.KeyType
	}{
		{"ec256", certcrypto.EC256},
		{"ec384", certcrypto.EC384},
		{"rsa2048", certcrypto.RSA2048},
		{"rsa4096", certcrypto.RSA4096},
		{"unknown", certcrypto.EC256}, // defaults to EC256
		{"", certcrypto.EC256},
	}
	for _, tt := range tests {
		got := specKeyType(tt.kt)
		if got != tt.want {
			t.Errorf("specKeyType(%q) = %v, want %v", tt.kt, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// buildDNSProvider: ensure each supported type constructs without error
// (credentials may be empty — we only verify no panic / type mismatch)
// ---------------------------------------------------------------------------

func TestBuildDNSProvider_SupportedTypes(t *testing.T) {
	// gcloud with only a project uses application default credentials. Point
	// them at a service account file for an unregistered account with a real
	// RSA key: building the provider reads the file but makes no network
	// request.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	serviceAccount, err := json.Marshal(map[string]string{
		"type":           "service_account",
		"project_id":     "my-proj",
		"private_key_id": "0",
		"private_key":    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		"client_email":   "sigil@my-proj.iam.gserviceaccount.com",
		"client_id":      "0",
		"token_uri":      "https://oauth2.googleapis.com/token",
	})
	if err != nil {
		t.Fatal(err)
	}
	credentials := filepath.Join(t.TempDir(), "service-account.json")
	if err := os.WriteFile(credentials, serviceAccount, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credentials)

	tests := []struct {
		name     string
		provider config.DNSProvider
		wantErr  bool
	}{
		{
			name: "cloudflare with api_token",
			provider: config.DNSProvider{
				Type:   "cloudflare",
				Config: map[string]any{"api_token": "tok"},
			},
		},
		{
			name: "aliyun",
			provider: config.DNSProvider{
				Type:   "aliyun",
				Config: map[string]any{"access_key": "k", "access_secret": "s"},
			},
		},
		{
			name: "tencentcloud",
			provider: config.DNSProvider{
				Type:   "tencentcloud",
				Config: map[string]any{"secret_id": "id", "secret_key": "k"},
			},
		},
		{
			name: "gcloud with project and application default credentials",
			provider: config.DNSProvider{
				Type:   "gcloud",
				Config: map[string]any{"project": "my-proj"},
			},
		},
		{
			name: "gcloud without project or service_account_file",
			provider: config.DNSProvider{
				Type:   "gcloud",
				Config: map[string]any{},
			},
			wantErr: true,
		},
		{
			name: "route53",
			provider: config.DNSProvider{
				Type: "route53",
				Config: map[string]any{
					"access_key": "ak",
					"secret_key": "sk",
					"region":     "us-east-1",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := buildDNSProvider(tt.provider)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p == nil {
				t.Fatal("provider is nil")
			}
		})
	}
}

func TestBuildDNSProviderBoundsPropagationWait(t *testing.T) {
	// lego reads these defaults from the environment without an upper limit.
	// Sigil's explicit bounds must win.
	for _, prefix := range []string{"CLOUDFLARE_", "ALICLOUD_", "TENCENTCLOUD_", "AWS_"} {
		t.Setenv(prefix+"PROPAGATION_TIMEOUT", "999999")
		t.Setenv(prefix+"POLLING_INTERVAL", "999999")
	}
	for _, p := range []config.DNSProvider{
		{Type: "cloudflare", Config: map[string]any{"api_token": "tok"}},
		{Type: "aliyun", Config: map[string]any{"access_key": "k", "access_secret": "s"}},
		{Type: "tencentcloud", Config: map[string]any{"secret_id": "id", "secret_key": "k"}},
		{Type: "route53", Config: map[string]any{"access_key": "ak", "secret_key": "sk", "region": "us-east-1"}},
		{Type: "exec", Command: []string{"/usr/local/bin/dns-hook"}},
	} {
		provider, err := buildDNSProvider(p)
		if err != nil {
			t.Fatalf("%s: %v", p.Type, err)
		}
		bounded, ok := provider.(challenge.ProviderTimeout)
		if !ok {
			t.Fatalf("%s provider does not report its propagation timeout", p.Type)
		}
		timeout, interval := bounded.Timeout()
		if timeout != dnsPropagationTimeout || interval != dnsPollingInterval {
			t.Errorf("%s: Timeout() = (%v, %v), want (%v, %v)",
				p.Type, timeout, interval, dnsPropagationTimeout, dnsPollingInterval)
		}
	}
}

func TestBuildDNSProvider_UnknownType(t *testing.T) {
	_, err := buildDNSProvider(config.DNSProvider{Type: "madeup"})
	if err == nil {
		t.Fatal("expected error for unknown type, got nil")
	}
	if !strings.Contains(err.Error(), "madeup") {
		t.Fatalf("error should mention type name, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// parseECDSAKey round-trip
// ---------------------------------------------------------------------------

func TestParseECDSAKey_RoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	got, err := parseECDSAKey(keyPEM)
	if err != nil {
		t.Fatalf("parseECDSAKey: %v", err)
	}
	if got.D.Cmp(priv.D) != 0 {
		t.Error("key mismatch after round-trip")
	}
}

func TestParseECDSAKey_Invalid(t *testing.T) {
	_, err := parseECDSAKey([]byte("not pem"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestAccountKeyRotatesWhenDirectoryChanges(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	issuer := NewIssuer(db.Accounts)
	ctx := context.Background()
	first, err := issuer.loadOrCreateAccountKey(ctx, "le", "https://old.example/directory", "ops@example.com")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := db.Accounts.Get(ctx, "le", nil)
	if err != nil {
		t.Fatal(err)
	}
	rec.RegistrationJSON = `{"uri":"https://old.example/account/1"}`
	if err := db.Accounts.Upsert(ctx, rec, nil); err != nil {
		t.Fatal(err)
	}

	second, err := issuer.loadOrCreateAccountKey(ctx, "le", "https://new.example/directory", "ops@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if first.D.Cmp(second.D) == 0 {
		t.Fatal("ACME account key was reused across directory identities")
	}
	rotated, err := db.Accounts.Get(ctx, "le", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Directory != "https://new.example/directory" || rotated.RegistrationJSON != "" {
		t.Fatalf("rotated account = %+v", rotated)
	}
}

// ---------------------------------------------------------------------------
// Account initialization under concurrent issuance
// ---------------------------------------------------------------------------

// fakeACME answers what ACME account initialization and ordering send. Like
// a CA it checks every JWS signature against the key of the account the
// request names. It fails every new order, so Issue stops before any
// challenge, but first holds each new-order request until orders requests
// are in flight together.
type fakeACME struct {
	*httptest.Server
	orders int

	mu        sync.Mutex
	nonces    int
	keys      map[string]*ecdsa.PublicKey // by account URL
	accounts  []string                    // account URL answering each new-account request
	orderKIDs []string                    // account URL of each verified new-order request
	arrivals  int
	problems  []string
	together  chan struct{}
	closeOnce sync.Once
}

func newFakeACME(t *testing.T, orders int) *fakeACME {
	t.Helper()
	f := &fakeACME{orders: orders, keys: map[string]*ecdsa.PublicKey{}, together: make(chan struct{})}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /dir", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   f.URL + "/nonce",
			"newAccount": f.URL + "/new-acct",
			"newOrder":   f.URL + "/new-order",
			"revokeCert": f.URL + "/revoke-cert",
			"keyChange":  f.URL + "/key-change",
		})
	})
	mux.HandleFunc("HEAD /nonce", func(w http.ResponseWriter, r *http.Request) { f.setNonce(w) })
	mux.HandleFunc("POST /new-acct", f.newAccount)
	mux.HandleFunc("POST /new-order", f.newOrder)
	f.Server = httptest.NewTLSServer(mux)
	t.Cleanup(f.Close)

	// lego's HTTP client trusts exactly the certificates in this file.
	caFile := filepath.Join(t.TempDir(), "acme-server.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.Certificate().Raw})
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LEGO_CA_CERTIFICATES", caFile)
	return f
}

func (f *fakeACME) setNonce(w http.ResponseWriter) {
	f.mu.Lock()
	f.nonces++
	nonce := fmt.Sprintf("nonce-%d", f.nonces)
	f.mu.Unlock()
	w.Header().Set("Replay-Nonce", nonce)
}

func (f *fakeACME) problem(w http.ResponseWriter, format string, args ...any) {
	f.setNonce(w)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":   "urn:ietf:params:acme:error:unauthorized",
		"detail": fmt.Sprintf(format, args...),
		"status": http.StatusForbidden,
	})
}

func (f *fakeACME) reject(w http.ResponseWriter, format string, args ...any) {
	f.mu.Lock()
	f.problems = append(f.problems, fmt.Sprintf(format, args...))
	f.mu.Unlock()
	f.problem(w, format, args...)
}

// verify checks the signature of the flattened JWS in r's body against its
// embedded jwk or, for a kid, the key registered for that account. It returns
// the kid and the key.
func (f *fakeACME) verify(r *http.Request) (string, *ecdsa.PublicKey, error) {
	var jws struct{ Protected, Payload, Signature string }
	if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
		return "", nil, err
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(jws.Protected)
	if err != nil {
		return "", nil, err
	}
	var header struct {
		KID string `json:"kid"`
		JWK *struct {
			X, Y string
		} `json:"jwk"`
	}
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		return "", nil, err
	}
	var key *ecdsa.PublicKey
	if header.JWK != nil {
		x, errX := base64.RawURLEncoding.DecodeString(header.JWK.X)
		y, errY := base64.RawURLEncoding.DecodeString(header.JWK.Y)
		if errX != nil || errY != nil {
			return "", nil, fmt.Errorf("bad jwk")
		}
		if key, err = ecdsa.ParseUncompressedPublicKey(elliptic.P256(), slices.Concat([]byte{4}, x, y)); err != nil {
			return "", nil, err
		}
	} else {
		f.mu.Lock()
		key = f.keys[header.KID]
		f.mu.Unlock()
		if key == nil {
			return "", nil, fmt.Errorf("unknown account %q", header.KID)
		}
	}
	sig, err := base64.RawURLEncoding.DecodeString(jws.Signature)
	if err != nil || len(sig) != 64 {
		return "", nil, fmt.Errorf("bad ES256 signature encoding")
	}
	digest := sha256.Sum256([]byte(jws.Protected + "." + jws.Payload))
	if !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return "", nil, fmt.Errorf("signature does not match the key of account %q", header.KID)
	}
	return header.KID, key, nil
}

func (f *fakeACME) newAccount(w http.ResponseWriter, r *http.Request) {
	_, key, err := f.verify(r)
	if err != nil {
		f.reject(w, "new-account: %v", err)
		return
	}
	// Answer slowly, so that without the account lock every concurrent
	// issuance reads the store before the first registration reaches it.
	time.Sleep(150 * time.Millisecond)
	f.mu.Lock()
	// Like a CA (RFC 8555, section 7.3), answer a known key with its account.
	status, account := http.StatusOK, ""
	for url, known := range f.keys {
		if known.Equal(key) {
			account = url
		}
	}
	if account == "" {
		status, account = http.StatusCreated, fmt.Sprintf("%s/acct/%d", f.URL, len(f.keys)+1)
		f.keys[account] = key
	}
	f.accounts = append(f.accounts, account)
	f.mu.Unlock()

	f.setNonce(w)
	w.Header().Set("Location", account)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"status":"valid"}`)
}

func (f *fakeACME) newOrder(w http.ResponseWriter, r *http.Request) {
	kid, _, err := f.verify(r)
	f.mu.Lock()
	if err == nil {
		f.orderKIDs = append(f.orderKIDs, kid)
	} else {
		f.problems = append(f.problems, fmt.Sprintf("new-order: %v", err))
	}
	f.arrivals++
	if f.arrivals == f.orders {
		f.closeOnce.Do(func() { close(f.together) })
	}
	f.mu.Unlock()

	select {
	case <-f.together:
	case <-time.After(5 * time.Second):
		f.mu.Lock()
		f.problems = append(f.problems, fmt.Sprintf(
			"only %d of %d orders were in flight together: account initialization blocks ordering", f.arrivals, f.orders))
		f.mu.Unlock()
		f.closeOnce.Do(func() { close(f.together) })
	}
	f.problem(w, "the fake ACME server issues no certificates")
}

func TestIssueInitializesTheAccountOnceForConcurrentIssuances(t *testing.T) {
	const n = 8
	server := newFakeACME(t, n)
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	issuer := NewIssuer(db.Accounts)
	cfg := &config.ServerConfig{
		ACME: config.ACMESection{
			Email:     "ops@example.com",
			DefaultCA: "fake",
			CAs:       map[string]config.CAEntry{"fake": {Directory: server.URL + "/dir"}},
		},
		// Never run: every order fails before the challenge.
		DNSProviders: map[string]config.DNSProvider{"hook": {Type: "exec", Command: []string{"/usr/local/bin/dns-hook"}}},
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, n)
	for i := range n {
		spec := config.CertificateSpec{
			Name:        fmt.Sprintf("cert-%d", i),
			Domains:     []string{fmt.Sprintf("host%d.example.com", i)},
			CA:          "fake",
			DNSProvider: "hook",
			KeyType:     "ec256",
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, errs[i] = issuer.Issue(context.Background(), cfg, spec)
		}()
	}
	close(start)
	wg.Wait()

	server.mu.Lock()
	defer server.mu.Unlock()
	for _, problem := range server.problems {
		t.Errorf("fake ACME server: %s", problem)
	}
	if len(server.accounts) != 1 {
		t.Fatalf("%d new-account requests, want 1", len(server.accounts))
	}
	account := server.accounts[0]
	if len(server.orderKIDs) != n {
		t.Fatalf("%d verified orders, want %d; Issue errors: %v", len(server.orderKIDs), n, errs)
	}
	for _, kid := range server.orderKIDs {
		if kid != account {
			t.Errorf("order signed for account %q, want %q", kid, account)
		}
	}

	rec, err := db.Accounts.Get(context.Background(), "fake", nil)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := parseECDSAKey([]byte(rec.KeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	if !stored.PublicKey.Equal(server.keys[account]) {
		t.Error("stored account key is not the key the account was registered with")
	}
	var reg registration.Resource
	if err := json.Unmarshal([]byte(rec.RegistrationJSON), &reg); err != nil {
		t.Fatal(err)
	}
	if reg.URI != account {
		t.Errorf("stored registration URI = %q, want %q", reg.URI, account)
	}
}

func TestStalledCADoesNotDelayAccountSetupForAnotherCA(t *testing.T) {
	ok := newFakeACME(t, 1)
	arrived, release := make(chan struct{}), make(chan struct{})
	var arrivedOnce sync.Once
	stalled := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrivedOnce.Do(func() { close(arrived) })
		<-release
		http.Error(w, "stalled", http.StatusServiceUnavailable)
	}))
	t.Cleanup(stalled.Close)
	// httptest serves one built-in certificate, which newFakeACME made lego
	// trust.
	if !bytes.Equal(stalled.Certificate().Raw, ok.Certificate().Raw) {
		t.Fatal("httptest servers no longer share a certificate: make lego trust the stalled server too")
	}

	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	issuer := NewIssuer(db.Accounts)
	cfg := &config.ServerConfig{
		ACME: config.ACMESection{
			Email:     "ops@example.com",
			DefaultCA: "ok",
			CAs: map[string]config.CAEntry{
				"stalled": {Directory: stalled.URL + "/dir"},
				"ok":      {Directory: ok.URL + "/dir"},
			},
		},
		// Never run: every order fails before the challenge.
		DNSProviders: map[string]config.DNSProvider{"hook": {Type: "exec", Command: []string{"/usr/local/bin/dns-hook"}}},
	}
	issue := func(ca string) error {
		_, err := issuer.Issue(context.Background(), cfg, config.CertificateSpec{
			Name:        ca,
			Domains:     []string{ca + ".example.com"},
			CA:          ca,
			DNSProvider: "hook",
			KeyType:     "ec256",
		})
		return err
	}

	var stalledErr, okErr error
	stalledDone, okDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stalledDone)
		stalledErr = issue("stalled")
	}()
	select {
	case <-arrived:
		// That issuance now holds its CA's account lock while lego waits for
		// the directory.
	case <-stalledDone:
		t.Fatalf("Issue for the stalled CA returned before reaching it: %v", stalledErr)
	}
	go func() {
		defer close(okDone)
		okErr = issue("ok")
	}()
	defer func() {
		close(release)
		<-stalledDone
		<-okDone
	}()

	select {
	case <-okDone:
	case <-time.After(10 * time.Second):
		t.Fatal("account setup for one CA waited for another CA's stalled directory request")
	}
	ok.mu.Lock()
	defer ok.mu.Unlock()
	for _, problem := range ok.problems {
		t.Errorf("fake ACME server: %s", problem)
	}
	if len(ok.accounts) != 1 || len(ok.orderKIDs) != 1 {
		t.Fatalf("CA ok: %d accounts and %d verified orders, want 1 and 1; Issue error: %v",
			len(ok.accounts), len(ok.orderKIDs), okErr)
	}
}

// errStoreDown stands for a database error other than a missing record.
var errStoreDown = errors.New("database unavailable")

// failingAccounts is an account store whose failAt-th Get fails with
// errStoreDown. It keeps the stored record as it was at that moment.
type failingAccounts struct {
	*store.AccountRepo
	failAt, gets int
	atFailure    *store.AccountRecord
}

func (s *failingAccounts) Get(ctx context.Context, ca string, tx *sql.Tx) (*store.AccountRecord, error) {
	s.gets++
	if s.gets != s.failAt {
		return s.AccountRepo.Get(ctx, ca, tx)
	}
	s.atFailure, _ = s.AccountRepo.Get(ctx, ca, tx)
	return nil, errStoreDown
}

func TestAccountStoreErrorsDoNotReplaceTheAccount(t *testing.T) {
	tests := []struct {
		name       string
		registered bool // an earlier issuance registered the account
		failAt     int  // which Get of the issuance fails
	}{
		{name: "reading the key", registered: true, failAt: 1},
		{name: "reading the registration", registered: true, failAt: 2},
		{name: "storing the registration", failAt: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newFakeACME(t, 1)
			db, err := store.Open(":memory:")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			ctx := context.Background()
			cfg := &config.ServerConfig{
				ACME: config.ACMESection{
					Email:     "ops@example.com",
					DefaultCA: "fake",
					CAs:       map[string]config.CAEntry{"fake": {Directory: server.URL + "/dir"}},
				},
				// Never run: every order fails before the challenge.
				DNSProviders: map[string]config.DNSProvider{"hook": {Type: "exec", Command: []string{"/usr/local/bin/dns-hook"}}},
			}
			spec := config.CertificateSpec{Name: "api", Domains: []string{"api.example.com"}, CA: "fake", DNSProvider: "hook", KeyType: "ec256"}
			if tt.registered {
				// The fake CA fails the order, after the account is registered.
				_, _ = NewIssuer(db.Accounts).Issue(ctx, cfg, spec)
			}

			accounts := &failingAccounts{AccountRepo: db.Accounts, failAt: tt.failAt}
			_, err = (&Issuer{accounts: accounts}).Issue(ctx, cfg, spec)
			if !errors.Is(err, errStoreDown) {
				t.Fatalf("Issue error = %v, want the store's error", err)
			}
			if accounts.atFailure == nil {
				t.Fatal("no account was stored when Get failed")
			}
			got, err := db.Accounts.Get(ctx, "fake", nil)
			if err != nil {
				t.Fatal(err)
			}
			if *got != *accounts.atFailure {
				t.Errorf("stored account changed after the failed read: key replaced %v, registration %q, was %q",
					got.KeyPEM != accounts.atFailure.KeyPEM, got.RegistrationJSON, accounts.atFailure.RegistrationJSON)
			}
			server.mu.Lock()
			defer server.mu.Unlock()
			if len(server.accounts) != 1 {
				t.Errorf("%d new-account requests, want 1", len(server.accounts))
			}
		})
	}
}

func TestDamagedStoredRegistrationIsRepairedWithTheSameAccount(t *testing.T) {
	server := newFakeACME(t, 1)
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	cfg := &config.ServerConfig{
		ACME: config.ACMESection{
			Email:     "ops@example.com",
			DefaultCA: "fake",
			CAs:       map[string]config.CAEntry{"fake": {Directory: server.URL + "/dir"}},
		},
		// Never run: every order fails before the challenge.
		DNSProviders: map[string]config.DNSProvider{"hook": {Type: "exec", Command: []string{"/usr/local/bin/dns-hook"}}},
	}
	spec := config.CertificateSpec{Name: "api", Domains: []string{"api.example.com"}, CA: "fake", DNSProvider: "hook", KeyType: "ec256"}
	issuer := NewIssuer(db.Accounts)
	// The fake CA fails the order, after the account is registered.
	_, _ = issuer.Issue(ctx, cfg, spec)
	rec, err := db.Accounts.Get(ctx, "fake", nil)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := rec.KeyPEM
	rec.RegistrationJSON = `{"uri":`
	if err := db.Accounts.Upsert(ctx, rec, nil); err != nil {
		t.Fatal(err)
	}

	_, issueErr := issuer.Issue(ctx, cfg, spec)

	rec, err = db.Accounts.Get(ctx, "fake", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec.KeyPEM != keyPEM {
		t.Error("the account key was replaced")
	}
	var reg registration.Resource
	if err := json.Unmarshal([]byte(rec.RegistrationJSON), &reg); err != nil {
		t.Fatalf("stored registration still does not parse (%v); Issue error: %v", err, issueErr)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	// The fake CA answers a known key with its account, as a real one does.
	if len(server.accounts) != 2 || server.accounts[1] != server.accounts[0] {
		t.Fatalf("new-account requests answered with %q, want the same account twice", server.accounts)
	}
	if reg.URI != server.accounts[0] {
		t.Errorf("stored registration URI = %q, want %q", reg.URI, server.accounts[0])
	}
	if len(server.orderKIDs) != 2 {
		t.Errorf("%d verified orders, want 2; Issue error: %v", len(server.orderKIDs), issueErr)
	}
}

// ---------------------------------------------------------------------------
// certNotAfter
// ---------------------------------------------------------------------------

func TestCertNotAfter(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	want := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     want,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	got := certNotAfter(certPEM)
	diff := got.Sub(want)
	if diff < 0 {
		diff = -diff
	}
	if diff > time.Second {
		t.Errorf("certNotAfter: got %v, want %v (diff %v)", got, want, diff)
	}
}

func TestCertNotAfter_Invalid(t *testing.T) {
	got := certNotAfter([]byte("garbage"))
	if !got.IsZero() {
		t.Errorf("expected zero time for invalid PEM, got %v", got)
	}
}
