package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/challenge"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

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
			// Without a service account file, gcloud falls back to env-based ADC
			// which is unavailable in unit tests; we expect an error here.
			name: "gcloud without service_account_file",
			provider: config.DNSProvider{
				Type:   "gcloud",
				Config: map[string]any{"project": "my-proj"},
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
