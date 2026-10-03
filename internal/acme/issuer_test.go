package acme

import (
	"bytes"
	"context"
	"crypto"
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
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/registration"
	"github.com/miekg/dns"

	"github.com/Oganneson-Studio/certfold/internal/config"
	"github.com/Oganneson-Studio/certfold/internal/store"
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
	const childEnv = "CERTFOLD_TEST_SET_DNS_RESOLVERS"
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

	const zone = "zone.certfold.test."
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

// writeServiceAccount writes a service account file of project "my-proj" for
// an unregistered account with a real RSA key, whose tokens come from
// tokenURI, and returns its path. Building a gcloud provider reads the file
// but makes no network request.
func writeServiceAccount(t *testing.T, tokenURI string) string {
	t.Helper()
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
		"client_email":   "certfold@my-proj.iam.gserviceaccount.com",
		"client_id":      "0",
		"token_uri":      tokenURI,
	})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "service-account.json")
	if err := os.WriteFile(file, serviceAccount, 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestBuildDNSProvider_SupportedTypes(t *testing.T) {
	// gcloud with only a project uses application default credentials. Point
	// them at a service account file.
	credentials := writeServiceAccount(t, "https://oauth2.googleapis.com/token")
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
			name: "gcloud with service_account_file",
			provider: config.DNSProvider{
				Type:   "gcloud",
				Config: map[string]any{"service_account_file": credentials},
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
			p, err := buildDNSProvider(context.Background(), tt.provider)
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
	// Certfold's explicit bounds must win.
	for _, prefix := range []string{"CLOUDFLARE_", "ALICLOUD_", "TENCENTCLOUD_", "AWS_", "GCE_"} {
		t.Setenv(prefix+"PROPAGATION_TIMEOUT", "999999")
		t.Setenv(prefix+"POLLING_INTERVAL", "999999")
	}
	serviceAccount := writeServiceAccount(t, "https://oauth2.googleapis.com/token")
	for _, p := range []config.DNSProvider{
		{Type: "cloudflare", Config: map[string]any{"api_token": "tok"}},
		{Type: "aliyun", Config: map[string]any{"access_key": "k", "access_secret": "s"}},
		{Type: "tencentcloud", Config: map[string]any{"secret_id": "id", "secret_key": "k"}},
		{Type: "route53", Config: map[string]any{"access_key": "ak", "secret_key": "sk", "region": "us-east-1"}},
		{Type: "gcloud", Config: map[string]any{"service_account_file": serviceAccount}},
		{Type: "exec", Command: []string{"/usr/local/bin/dns-hook"}},
	} {
		provider, err := buildDNSProvider(context.Background(), p)
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

// TestBuildDNSProviderGcloudProject checks which project the gcloud provider
// manages: the configured one, else the service account file's. A token
// endpoint that always fails stops each request before it leaves the test, and
// lego's error names the request's URL.
func TestBuildDNSProviderGcloudProject(t *testing.T) {
	tokens := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no token", http.StatusInternalServerError)
	}))
	defer tokens.Close()
	serviceAccount := writeServiceAccount(t, tokens.URL)
	// A zone ID makes lego ask the API for the zone instead of looking it
	// up in DNS first.
	t.Setenv("GCE_ZONE_ID", "zone")

	for _, tt := range []struct {
		project, want string
	}{
		{"", "my-proj"},
		{"other-proj", "other-proj"},
	} {
		p, err := buildDNSProvider(context.Background(), config.DNSProvider{
			Type:   "gcloud",
			Config: map[string]any{"service_account_file": serviceAccount, "project": tt.project},
		})
		if err != nil {
			t.Fatal(err)
		}
		err = p.Present("www.certfold.test", "token", "keyAuth")
		if err == nil || !strings.Contains(err.Error(), "/projects/"+tt.want+"/managedZones/zone") {
			t.Errorf("project %q: Present error = %v, want a request for project %s", tt.project, err, tt.want)
		}
	}
}

// failingProvider fails Present and CleanUp with err.
type failingProvider struct{ err error }

func (p failingProvider) Present(_, _, _ string) error { return p.err }
func (p failingProvider) CleanUp(_, _, _ string) error { return p.err }
func (p failingProvider) Timeout() (timeout, interval time.Duration) {
	return dnsPropagationTimeout, dnsPollingInterval
}

func TestBuildDNSProviderRedactsCredentialsFromErrors(t *testing.T) {
	for _, p := range []config.DNSProvider{
		// An empty value must not be replaced, and one value starting
		// another must not leave the other's tail.
		{Type: "cloudflare", Config: map[string]any{"api_token": "cf-token", "zone_api_token": "", "auth_key": "cf-token-key"}},
		{Type: "aliyun", Config: map[string]any{"access_key": "ali-id", "access_secret": "ali-secret"}},
		{Type: "tencentcloud", Config: map[string]any{"secret_id": "tc-id", "secret_key": "tc-secret"}},
		// Swapped: AWS quotes the "access key ID", here the secret.
		{Type: "route53", Config: map[string]any{"access_key": "aws-secret", "secret_key": "AKIAEXAMPLE", "region": "us-east-1"}},
	} {
		provider, err := buildDNSProvider(context.Background(), p)
		if err != nil {
			t.Fatalf("%s: %v", p.Type, err)
		}
		redacting, ok := provider.(*redactingProvider)
		if !ok {
			t.Fatalf("%s: provider is a %T, want *redactingProvider", p.Type, provider)
		}
		var values []string
		for _, v := range p.Config {
			if v != "" {
				values = append(values, v.(string))
			}
		}
		slices.Sort(values)
		cause := errors.New("api: " + strings.Join(values, ", "))
		redacting.ProviderTimeout = failingProvider{err: cause}

		want := "api: " + strings.Join(slices.Repeat([]string{"REDACTED"}, len(values)), ", ")
		if p.Type == "route53" {
			// The region, sorted last, is no credential.
			want = "api: REDACTED, REDACTED, us-east-1"
		}
		for action, err := range map[string]error{
			"Present": redacting.Present("www.certfold.test", "token", "keyAuth"),
			"CleanUp": redacting.CleanUp("www.certfold.test", "token", "keyAuth"),
		} {
			if err == nil || err.Error() != want {
				t.Errorf("%s %s: error = %v, want %q", p.Type, action, err, want)
			}
			if errors.Unwrap(err) != nil {
				t.Errorf("%s %s: the error wraps the original", p.Type, action)
			}
		}
	}
}

func TestBuildDNSProviderRedactsRoute53CredentialsFromTheEnvironment(t *testing.T) {
	// Without keys in the config, the AWS SDK takes them from here; swapped.
	t.Setenv("AWS_ACCESS_KEY_ID", "aws-secret")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "AKIAEXAMPLE")
	t.Setenv("AWS_SESSION_TOKEN", "")
	provider, err := buildDNSProvider(context.Background(), config.DNSProvider{Type: "route53", Config: map[string]any{"region": "us-east-1"}})
	if err != nil {
		t.Fatal(err)
	}
	redacting := provider.(*redactingProvider)
	redacting.ProviderTimeout = failingProvider{err: errors.New("api: aws-secret, AKIAEXAMPLE, us-east-1")}
	if err := redacting.Present("www.certfold.test", "token", "keyAuth"); err == nil || err.Error() != "api: REDACTED, REDACTED, us-east-1" {
		t.Errorf("error = %v", err)
	}
}

func TestBuildDNSProviderRejectsGcloudImpersonation(t *testing.T) {
	t.Setenv("GCE_IMPERSONATE_SERVICE_ACCOUNT", "dns@other-proj.iam.gserviceaccount.com")
	_, err := buildDNSProvider(context.Background(), config.DNSProvider{Type: "gcloud", Config: map[string]any{"project": "my-proj"}})
	if err == nil || !strings.Contains(err.Error(), "GCE_IMPERSONATE_SERVICE_ACCOUNT") {
		t.Fatalf("err = %v, want the unsupported variable named", err)
	}
}

func TestBuildDNSProvider_UnknownType(t *testing.T) {
	_, err := buildDNSProvider(context.Background(), config.DNSProvider{Type: "madeup"})
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

	mu            sync.Mutex
	nonces        int
	keys          map[string]*ecdsa.PublicKey // by account URL
	accounts      []string                    // account URL answering each new-account request
	updates       []accountUpdate             // each verified account update
	orderKIDs     []string                    // account URL of each verified new-order request
	orderPayloads [][]byte                    // JSON payload of each verified new-order request
	// refuseAccounts, when set, makes new-account requests fail as a CA
	// refuses a registration.
	refuseAccounts bool
	// renewalInfo, when set by offerRenewalInfo, answers GET
	// /renewal-info/{id}, and the directory offers renewalInfo.
	renewalInfo http.HandlerFunc
	arrivals    int
	problems    []string
	together    chan struct{}
	closeOnce   sync.Once
}

func newFakeACME(t *testing.T, orders int) *fakeACME {
	t.Helper()
	f := &fakeACME{orders: orders, keys: map[string]*ecdsa.PublicKey{}, together: make(chan struct{})}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /dir", func(w http.ResponseWriter, r *http.Request) {
		dir := map[string]string{
			"newNonce":   f.URL + "/nonce",
			"newAccount": f.URL + "/new-acct",
			"newOrder":   f.URL + "/new-order",
			"revokeCert": f.URL + "/revoke-cert",
			"keyChange":  f.URL + "/key-change",
		}
		f.mu.Lock()
		if f.renewalInfo != nil {
			dir["renewalInfo"] = f.URL + "/renewal-info"
		}
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(dir)
	})
	mux.HandleFunc("GET /renewal-info/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		handler := f.renewalInfo
		f.mu.Unlock()
		if handler == nil {
			http.NotFound(w, r)
			return
		}
		handler(w, r)
	})
	mux.HandleFunc("HEAD /nonce", func(w http.ResponseWriter, r *http.Request) { f.setNonce(w) })
	mux.HandleFunc("POST /new-acct", f.newAccount)
	mux.HandleFunc("POST /acct/{id}", f.updateAccount)
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

// offerRenewalInfo makes the directory offer renewalInfo, served by handler.
func (f *fakeACME) offerRenewalInfo(handler http.HandlerFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.renewalInfo = handler
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
// the kid, the key and the decoded payload.
func (f *fakeACME) verify(r *http.Request) (string, *ecdsa.PublicKey, []byte, error) {
	var jws struct{ Protected, Payload, Signature string }
	if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
		return "", nil, nil, err
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(jws.Protected)
	if err != nil {
		return "", nil, nil, err
	}
	var header struct {
		KID string `json:"kid"`
		JWK *struct {
			X, Y string
		} `json:"jwk"`
	}
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		return "", nil, nil, err
	}
	var key *ecdsa.PublicKey
	if header.JWK != nil {
		x, errX := base64.RawURLEncoding.DecodeString(header.JWK.X)
		y, errY := base64.RawURLEncoding.DecodeString(header.JWK.Y)
		if errX != nil || errY != nil {
			return "", nil, nil, fmt.Errorf("bad jwk")
		}
		if key, err = ecdsa.ParseUncompressedPublicKey(elliptic.P256(), slices.Concat([]byte{4}, x, y)); err != nil {
			return "", nil, nil, err
		}
	} else {
		f.mu.Lock()
		key = f.keys[header.KID]
		f.mu.Unlock()
		if key == nil {
			return "", nil, nil, fmt.Errorf("unknown account %q", header.KID)
		}
	}
	sig, err := base64.RawURLEncoding.DecodeString(jws.Signature)
	if err != nil || len(sig) != 64 {
		return "", nil, nil, fmt.Errorf("bad ES256 signature encoding")
	}
	digest := sha256.Sum256([]byte(jws.Protected + "." + jws.Payload))
	if !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return "", nil, nil, fmt.Errorf("signature does not match the key of account %q", header.KID)
	}
	payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		return "", nil, nil, err
	}
	return header.KID, key, payload, nil
}

func (f *fakeACME) newAccount(w http.ResponseWriter, r *http.Request) {
	_, key, _, err := f.verify(r)
	if err != nil {
		f.reject(w, "new-account: %v", err)
		return
	}
	f.mu.Lock()
	refuse := f.refuseAccounts
	f.mu.Unlock()
	if refuse {
		f.problem(w, "the fake ACME server refuses new accounts")
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

// accountUpdate is a verified account update: the account it was signed for
// and the payload it sent.
type accountUpdate struct {
	kid     string
	payload string
}

// updateAccount answers an update of the account at the request URL, which
// must be the account the request is signed for.
func (f *fakeACME) updateAccount(w http.ResponseWriter, r *http.Request) {
	kid, _, payload, err := f.verify(r)
	if err == nil && kid != f.URL+r.URL.Path {
		err = fmt.Errorf("signed for account %q", kid)
	}
	if err != nil {
		f.reject(w, "update of %s: %v", r.URL.Path, err)
		return
	}
	f.mu.Lock()
	f.updates = append(f.updates, accountUpdate{kid: kid, payload: string(payload)})
	f.mu.Unlock()
	f.setNonce(w)
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"status":"valid"}`)
}

func (f *fakeACME) newOrder(w http.ResponseWriter, r *http.Request) {
	kid, _, payload, err := f.verify(r)
	f.mu.Lock()
	if err == nil {
		f.orderKIDs = append(f.orderKIDs, kid)
		f.orderPayloads = append(f.orderPayloads, payload)
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
	issuer := NewIssuer(context.Background(), db.Accounts)
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
			_, errs[i] = issuer.Issue(context.Background(), cfg, spec, nil)
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
	issuer := NewIssuer(context.Background(), db.Accounts)
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
		}, nil)
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

// failingAccounts is an account store whose Get fails with errStoreDown.
type failingAccounts struct{ *store.AccountRepo }

func (failingAccounts) Get(context.Context, string, *sql.Tx) (*store.AccountRecord, error) {
	return nil, errStoreDown
}

func TestAccountStoreErrorsDoNotReplaceTheAccount(t *testing.T) {
	for _, registered := range []bool{false, true} { // an earlier issuance registered the account
		t.Run(fmt.Sprintf("registered=%t", registered), func(t *testing.T) {
			server := newFakeACME(t, 1)
			db := openAccountStore(t)
			ctx := context.Background()
			cfg, spec := renewalInfoConfig(server.URL + "/dir")
			if registered {
				// The fake CA fails the order, after the account is registered.
				_, _ = NewIssuer(context.Background(), db.Accounts).Issue(ctx, cfg, spec, nil)
			}
			before, beforeErr := db.Accounts.Get(ctx, "fake", nil)

			_, err := (&Issuer{accounts: failingAccounts{db.Accounts}}).Issue(ctx, cfg, spec, nil)
			if !errors.Is(err, errStoreDown) {
				t.Fatalf("Issue error = %v, want the store's error", err)
			}
			after, afterErr := db.Accounts.Get(ctx, "fake", nil)
			switch {
			case !registered && !errors.Is(afterErr, sql.ErrNoRows):
				t.Errorf("an account was stored after the failed read: %v", afterErr)
			case registered && (beforeErr != nil || afterErr != nil):
				t.Fatal(beforeErr, afterErr)
			case registered && *after != *before:
				t.Errorf("stored account changed after the failed read: key replaced %v, registration %q, was %q",
					after.KeyPEM != before.KeyPEM, after.RegistrationJSON, before.RegistrationJSON)
			}
			want := 0
			if registered {
				want = 1
			}
			server.mu.Lock()
			defer server.mu.Unlock()
			if len(server.accounts) != want {
				t.Errorf("%d new-account requests, want %d", len(server.accounts), want)
			}
		})
	}
}

func openAccountStore(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// storedAccount returns the account stored for the CA "fake", and the key
// and account URL of its registration.
func storedAccount(t *testing.T, db *store.DB) (*store.AccountRecord, *ecdsa.PrivateKey, string) {
	t.Helper()
	rec, err := db.Accounts.Get(context.Background(), "fake", nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := parseECDSAKey([]byte(rec.KeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	var reg registration.Resource
	if err := json.Unmarshal([]byte(rec.RegistrationJSON), &reg); err != nil {
		t.Fatalf("stored registration %q: %v", rec.RegistrationJSON, err)
	}
	return rec, key, reg.URI
}

// An account belongs to the directory it was registered with: the account
// for a new directory has a new key, stored with its registration there.
func TestAccountKeyRotatesWhenDirectoryChanges(t *testing.T) {
	old, moved := newFakeACME(t, 1), newFakeACME(t, 1)
	db := openAccountStore(t)
	issuer := NewIssuer(context.Background(), db.Accounts)
	ctx := context.Background()
	cfg, spec := renewalInfoConfig(old.URL + "/dir")
	// The fake CAs fail the orders, after the account is registered.
	_, _ = issuer.Issue(ctx, cfg, spec, nil)
	_, firstKey, _ := storedAccount(t, db)

	cfg.ACME.CAs["fake"] = config.CAEntry{Directory: moved.URL + "/dir"}
	_, issueErr := issuer.Issue(ctx, cfg, spec, nil)
	rec, key, account := storedAccount(t, db)

	if key.Equal(firstKey) {
		t.Error("the account key was reused for another directory")
	}
	if rec.Directory != moved.URL+"/dir" {
		t.Errorf("stored directory = %q, want %q", rec.Directory, moved.URL+"/dir")
	}
	moved.mu.Lock()
	defer moved.mu.Unlock()
	if len(moved.accounts) != 1 || len(moved.orderKIDs) != 1 {
		t.Fatalf("new directory: %d accounts and %d verified orders, want 1 and 1; Issue error: %v",
			len(moved.accounts), len(moved.orderKIDs), issueErr)
	}
	if account != moved.accounts[0] || !key.PublicKey.Equal(moved.keys[account]) {
		t.Errorf("stored account %q is not the one registered with the new directory, %q", account, moved.accounts[0])
	}
}

// A new email address updates the contact of the account, which keeps its
// key: a new key would need a new registration, which a CA that binds
// accounts to a one-time external account binding refuses.
func TestEmailChangeUpdatesTheAccountContact(t *testing.T) {
	server := newFakeACME(t, 1)
	db := openAccountStore(t)
	issuer := NewIssuer(context.Background(), db.Accounts)
	ctx := context.Background()
	cfg, spec := renewalInfoConfig(server.URL + "/dir")
	// The fake CA fails the orders, after the account is registered.
	_, _ = issuer.Issue(ctx, cfg, spec, nil)
	_, firstKey, firstAccount := storedAccount(t, db)

	cfg.ACME.Email = "security@example.com"
	// The second finds the contact up to date.
	for range 2 {
		_, _ = issuer.Issue(ctx, cfg, spec, nil)
	}
	rec, key, account := storedAccount(t, db)

	if !key.Equal(firstKey) || account != firstAccount {
		t.Errorf("a new email address replaced the account %q by %q (key replaced %v)", firstAccount, account, !key.Equal(firstKey))
	}
	if rec.Email != "security@example.com" {
		t.Errorf("stored email = %q, want security@example.com", rec.Email)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	for _, problem := range server.problems {
		t.Errorf("fake ACME server: %s", problem)
	}
	if len(server.accounts) != 1 || len(server.orderKIDs) != 3 {
		t.Fatalf("%d new-account requests and %d verified orders, want 1 and 3", len(server.accounts), len(server.orderKIDs))
	}
	want := accountUpdate{kid: firstAccount, payload: `{"contact":["mailto:security@example.com"]}`}
	if len(server.updates) != 1 || server.updates[0] != want {
		t.Errorf("account updates = %+v, want one: %+v", server.updates, want)
	}
}

// Only an account the CA registered is stored: a registration it refuses
// stores nothing, and leaves the account stored for another directory as it
// was.
func TestRefusedRegistrationStoresNothing(t *testing.T) {
	registering, refusing := newFakeACME(t, 1), newFakeACME(t, 1)
	refusing.mu.Lock()
	refusing.refuseAccounts = true
	refusing.mu.Unlock()
	db := openAccountStore(t)
	issuer := NewIssuer(context.Background(), db.Accounts)
	ctx := context.Background()
	cfg, spec := renewalInfoConfig(refusing.URL + "/dir")

	if _, err := issuer.Issue(ctx, cfg, spec, nil); err == nil || !strings.Contains(err.Error(), "register: ") {
		t.Fatalf("Issue error = %v, want a refused registration", err)
	}
	if _, err := db.Accounts.Get(ctx, "fake", nil); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("stored account after the refused registration: %v, want none", err)
	}

	cfg.ACME.CAs["fake"] = config.CAEntry{Directory: registering.URL + "/dir"}
	// The fake CA fails the order, after the account is registered.
	_, _ = issuer.Issue(ctx, cfg, spec, nil)
	before, _, _ := storedAccount(t, db)
	cfg.ACME.CAs["fake"] = config.CAEntry{Directory: refusing.URL + "/dir"}
	if _, err := issuer.Issue(ctx, cfg, spec, nil); err == nil || !strings.Contains(err.Error(), "register: ") {
		t.Fatalf("Issue error = %v, want a refused registration", err)
	}
	if after, _, _ := storedAccount(t, db); *after != *before {
		t.Errorf("the refused registration replaced the stored account: key replaced %v, directory %q",
			after.KeyPEM != before.KeyPEM, after.Directory)
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
	issuer := NewIssuer(context.Background(), db.Accounts)
	// The fake CA fails the order, after the account is registered.
	_, _ = issuer.Issue(ctx, cfg, spec, nil)
	rec, err := db.Accounts.Get(ctx, "fake", nil)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := rec.KeyPEM
	rec.RegistrationJSON = `{"uri":`
	if err := db.Accounts.Upsert(ctx, rec, nil); err != nil {
		t.Fatal(err)
	}

	_, issueErr := issuer.Issue(ctx, cfg, spec, nil)

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

// cancellingAccounts is an account store that cancels the issuance's ctx as
// soon as the account is read: shutdown, or an IPC caller that leaves, while
// lego registers the account, which it does not interrupt.
type cancellingAccounts struct {
	*store.AccountRepo
	cancel context.CancelFunc
}

func (s cancellingAccounts) Get(ctx context.Context, ca string, tx *sql.Tx) (*store.AccountRecord, error) {
	defer s.cancel()
	return s.AccountRepo.Get(ctx, ca, tx)
}

// An account the CA has registered is stored even when the caller leaves
// during the registration: its key is otherwise lost, and the next issuance
// registers another account, which a CA that binds accounts to a one-time
// external account binding refuses.
func TestRegisteredAccountIsStoredWhenTheCallerLeaves(t *testing.T) {
	server := newFakeACME(t, 1)
	db := openAccountStore(t)
	cfg, spec := renewalInfoConfig(server.URL + "/dir")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The fake CA fails the order, after the account is registered.
	_, _ = (&Issuer{accounts: cancellingAccounts{db.Accounts, cancel}}).Issue(ctx, cfg, spec, nil)
	_, _ = NewIssuer(context.Background(), db.Accounts).Issue(context.Background(), cfg, spec, nil)

	server.mu.Lock()
	defer server.mu.Unlock()
	for _, problem := range server.problems {
		t.Errorf("fake ACME server: %s", problem)
	}
	if len(server.keys) != 1 {
		t.Fatalf("the CA registered %d accounts, want 1: the first registration was not stored", len(server.keys))
	}
	_, key, account := storedAccount(t, db)
	if account != server.accounts[0] || !key.PublicKey.Equal(server.keys[account]) {
		t.Errorf("stored account %q is not the one the CA registered first, %q", account, server.accounts[0])
	}
}

// ---------------------------------------------------------------------------
// newResult
// ---------------------------------------------------------------------------

// A certificate the CA issued is handed on only if it is for the private key
// of the order and names every ordered domain: lego checks neither, and the
// clients install the two as a pair.
func TestNewResultChecksTheIssuedCertificate(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	notAfter := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	// Configured domains may hold capitals; a CA answers in lower case.
	domains := []string{"api.example.com", "*.Example.com"}
	ordered := []string{"api.example.com", "*.example.com"}
	tests := []struct {
		name     string
		certKey  crypto.Signer // the key the certificate is for
		orderKey crypto.Signer // the private key lego generated for the order
		dnsNames []string
		want     string // in the error; none if empty
	}{
		{name: "ECDSA as ordered", certKey: ecKey, orderKey: ecKey, dnsNames: ordered},
		{name: "RSA as ordered", certKey: rsaKey, orderKey: rsaKey, dnsNames: ordered},
		{name: "names in another order and more", certKey: ecKey, orderKey: ecKey,
			dnsNames: []string{"www.example.com", "*.example.com", "api.example.com"}},
		{name: "for another key", certKey: otherKey, orderKey: ecKey, dnsNames: ordered,
			want: "issued certificate is not for the private key of the order"},
		{name: "for a key of another type", certKey: rsaKey, orderKey: ecKey, dnsNames: ordered,
			want: "issued certificate is not for the private key of the order"},
		{name: "a domain missing", certKey: ecKey, orderKey: ecKey, dnsNames: []string{"api.example.com"},
			want: "issued certificate does not name *.Example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tpl := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
				NotAfter:     notAfter,
				DNSNames:     tt.dnsNames,
			}
			der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, tt.certKey.Public(), tt.certKey)
			if err != nil {
				t.Fatal(err)
			}
			res := &certificate.Resource{
				Domain:      "api.example.com",
				Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
				PrivateKey:  certcrypto.PEMEncode(tt.orderKey),
			}

			got, err := newResult(res, domains)
			if tt.want != "" {
				if err == nil || err.Error() != tt.want {
					t.Fatalf("newResult error = %v, want %q", err, tt.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("newResult: %v", err)
			}
			if !bytes.Equal(got.Certificate, res.Certificate) || !bytes.Equal(got.PrivateKey, res.PrivateKey) || !got.NotAfter.Equal(notAfter) {
				t.Errorf("newResult = %+v, want the issued pair, expiring %s", got, notAfter)
			}
		})
	}

	if _, err := newResult(&certificate.Resource{Certificate: []byte("garbage")}, domains); err == nil || !strings.HasPrefix(err.Error(), "issued certificate: ") {
		t.Errorf("newResult of a certificate that does not parse: error = %v", err)
	}
}
