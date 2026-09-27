package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/pkg/proto"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type testIdentityCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM string
}

func newTestIdentityCA(t *testing.T, now time.Time) *testIdentityCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Identity CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testIdentityCA{
		cert:    cert,
		key:     key,
		certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}
}

func (authority *testIdentityCA) issue(t *testing.T, name string, publicKey any, now, notAfter time.Time, serial int64) string {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, authority.cert, publicKey, authority.key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func privateKeyPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// buildTestCfg builds a minimal ClientConfig that points at serverURL.
func buildTestCfg(t *testing.T, serverURL string) *config.ClientConfig {
	t.Helper()
	return &config.ClientConfig{
		Client: config.ClientSection{
			Name:         "web-1",
			ServerURL:    serverURL,
			PullInterval: time.Hour,
			DataDir:      t.TempDir(),
		},
		Outputs: map[string][]config.OutputSpec{},
	}
}

// fakeServer simulates the sigils HTTP API for client tests.
type fakeServer struct {
	summaries  []proto.CertSummary
	bundles    map[string]*proto.CertBundle
	heartbeats int
}

func (f *fakeServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/certificates", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(f.summaries)
	})
	mux.HandleFunc("/v1/certificates/", func(w http.ResponseWriter, r *http.Request) {
		// /v1/certificates/{name}/bundle
		name := r.URL.Path[len("/v1/certificates/"):]
		if len(name) > 7 && name[len(name)-7:] == "/bundle" {
			name = name[:len(name)-7]
		}
		b, ok := f.bundles[name]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(b)
	})
	mux.HandleFunc("/v1/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		f.heartbeats++
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestPullOnce_FetchAndWrite(t *testing.T) {
	fs := &fakeServer{
		summaries: []proto.CertSummary{
			{Name: "api-prod", Fingerprint: "sha256:AABB", NotAfter: time.Now().Add(90 * 24 * time.Hour)},
		},
		bundles: map[string]*proto.CertBundle{
			"api-prod": {
				Name:         "api-prod",
				FullchainPEM: "-----BEGIN CERTIFICATE-----\nMIIBa...\n-----END CERTIFICATE-----\n",
				KeyPEM:       "-----BEGIN PRIVATE KEY-----\nMIIB...\n-----END PRIVATE KEY-----\n",
			},
		},
	}
	ts := httptest.NewServer(fs.handler())
	defer ts.Close()

	cfg := buildTestCfg(t, ts.URL)
	// Add an output spec for api-prod.
	outPath := filepath.Join(t.TempDir(), "cert.pem")
	cfg.Outputs["api-prod"] = []config.OutputSpec{
		{Format: "pem-fullchain", Path: outPath},
	}

	c := &Client{cfg: cfg, http: ts.Client()}
	if err := c.pullOnce(context.Background()); err != nil {
		t.Fatalf("pullOnce: %v", err)
	}

	// Output file should exist.
	if _, err := os.Stat(outPath); err != nil {
		t.Errorf("output file not written: %v", err)
	}

	// State should be persisted.
	st := c.loadState()
	if st.Certs["api-prod"] != "sha256:AABB" {
		t.Errorf("state not updated: %v", st.Certs)
	}

	// Heartbeat should have been sent.
	if fs.heartbeats != 1 {
		t.Errorf("expected 1 heartbeat, got %d", fs.heartbeats)
	}
}

func TestPullOnce_NoChangeSkipsWrite(t *testing.T) {
	fs := &fakeServer{
		summaries: []proto.CertSummary{
			{Name: "api-prod", Fingerprint: "sha256:AABB"},
		},
		bundles: map[string]*proto.CertBundle{
			"api-prod": {FullchainPEM: "-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----\n", KeyPEM: "key"},
		},
	}
	ts := httptest.NewServer(fs.handler())
	defer ts.Close()

	outPath := filepath.Join(t.TempDir(), "cert.pem")
	cfg := buildTestCfg(t, ts.URL)
	cfg.Outputs["api-prod"] = []config.OutputSpec{
		{Format: "pem-fullchain", Path: outPath},
	}

	c := &Client{cfg: cfg, http: ts.Client()}

	// First pull — writes the cert.
	_ = c.pullOnce(context.Background())
	info1, _ := os.Stat(outPath)

	// Simulate a time gap.
	time.Sleep(5 * time.Millisecond)

	// Second pull — fingerprint unchanged, should NOT rewrite.
	_ = c.pullOnce(context.Background())
	info2, _ := os.Stat(outPath)

	if info1 != nil && info2 != nil && info1.ModTime() != info2.ModTime() {
		t.Error("file was rewritten when fingerprint did not change")
	}
}

func TestPullOnce_NoBundleCachesToDataDir(t *testing.T) {
	fs := &fakeServer{
		summaries: []proto.CertSummary{
			{Name: "tls-internal", Fingerprint: "sha256:CC"},
		},
		bundles: map[string]*proto.CertBundle{
			"tls-internal": {FullchainPEM: "-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----\n", KeyPEM: "key"},
		},
	}
	ts := httptest.NewServer(fs.handler())
	defer ts.Close()

	cfg := buildTestCfg(t, ts.URL)
	// No outputs configured for tls-internal → should be cached.
	c := &Client{cfg: cfg, http: ts.Client()}
	_ = c.pullOnce(context.Background())

	cached := filepath.Join(cfg.Client.DataDir, "cache", "tls-internal", "fullchain.pem")
	if _, err := os.Stat(cached); err != nil {
		t.Errorf("cache file not written: %v", err)
	}
}

func TestPullOnce_ServerError_Tolerant(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer ts.Close()

	cfg := buildTestCfg(t, ts.URL)
	c := &Client{cfg: cfg, http: ts.Client()}
	// pullOnce should return an error but not panic.
	err := c.pullOnce(context.Background())
	if err == nil {
		t.Error("expected error from server, got nil")
	}
}

func TestRenewIdentityPersistsBeforeRuntimeSwitch(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	authority := newTestIdentityCA(t, now)
	oldKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldCert := authority.issue(t, "web-1", &oldKey.PublicKey, now, now.Add(24*time.Hour), 2)
	cfg := buildTestCfg(t, "https://sigil.example.test")
	cfg.Client.IdentityRenewBefore = 30 * 24 * time.Hour
	cfg.Identity = config.IdentitySection{
		CACert:     authority.certPEM,
		ClientCert: oldCert,
		ClientKey:  privateKeyPEM(t, oldKey),
	}

	var c *Client
	var savedCert, savedKey string
	saverSawOldIdentity := false
	c, err = New(cfg, WithIdentitySaver(func(_ string, clientCert, clientKey string) error {
		c.cfgMu.RLock()
		saverSawOldIdentity = c.cfg.Identity.ClientCert == oldCert
		c.cfgMu.RUnlock()
		savedCert = clientCert
		savedKey = clientKey
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	c.now = func() time.Time { return now }
	c.http = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/v1/identity/renew" {
			t.Fatalf("request path = %q", req.URL.Path)
		}
		var renewalRequest proto.RenewIdentityRequest
		if err := json.NewDecoder(req.Body).Decode(&renewalRequest); err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode([]byte(renewalRequest.CSR))
		if block == nil {
			t.Fatal("renewal request has no CSR PEM")
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		newCert := authority.issue(t, "web-1", csr.PublicKey, now, now.Add(90*24*time.Hour), 3)
		responseBody, err := json.Marshal(proto.RenewIdentityResponse{ClientCert: newCert})
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader(responseBody)),
			Request:    req,
		}, nil
	})}

	if err := c.renewIdentityLocked(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !saverSawOldIdentity {
		t.Fatal("runtime identity changed before the renewed identity was persisted")
	}
	if savedCert == "" || savedKey == "" || savedCert == oldCert {
		t.Fatal("renewed identity was not persisted")
	}
	if _, err := tls.X509KeyPair([]byte(savedCert), []byte(savedKey)); err != nil {
		t.Fatalf("saved certificate and key do not match: %v", err)
	}
	c.cfgMu.RLock()
	runtimeCert := c.cfg.Identity.ClientCert
	c.cfgMu.RUnlock()
	if runtimeCert != savedCert {
		t.Fatal("runtime did not switch to the persisted identity")
	}
}

func TestFetchNamedCertificateForcesOnlyThatBundle(t *testing.T) {
	var bundleRequests []string
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/certificates", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]proto.CertSummary{
			{Name: "a", Fingerprint: "fp-a"},
			{Name: "b", Fingerprint: "fp-b"},
		})
	})
	mux.HandleFunc("/v1/certificates/", func(w http.ResponseWriter, r *http.Request) {
		bundleRequests = append(bundleRequests, r.URL.Path)
		_ = json.NewEncoder(w).Encode(proto.CertBundle{
			FullchainPEM: "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n",
			KeyPEM:       "key",
		})
	})
	mux.HandleFunc("/v1/heartbeat", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := &Client{cfg: buildTestCfg(t, ts.URL), http: ts.Client()}
	if err := c.saveState(&state{Certs: map[string]string{"a": "fp-a", "b": "fp-b"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.Fetch(context.Background(), "b"); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(bundleRequests) != 1 || bundleRequests[0] != "/v1/certificates/b/bundle" {
		t.Fatalf("bundle requests = %v, want only b", bundleRequests)
	}
}

func TestReloadAppliesRuntimeConfig(t *testing.T) {
	cfg := buildTestCfg(t, "https://old.example.com")
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	updated := buildTestCfg(t, "https://new.example.com")
	updated.Client.Name = "web-2"
	updated.Client.PullInterval = 2 * time.Hour
	if err := c.Reload(updated); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	status := c.Status()
	if status.Name != "web-2" || status.ServerURL != "https://new.example.com" {
		t.Fatalf("status after reload = %+v", status)
	}
	if got := c.pullInterval(); got != 2*time.Hour {
		t.Fatalf("pull interval = %v, want 2h", got)
	}
}

func TestReloadRejectsListenerChanges(t *testing.T) {
	cfg := buildTestCfg(t, "https://sigil.example.com")
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	updated := *cfg
	updated.Client = cfg.Client
	updated.Client.IPCSocket = "changed.sock"
	if err := c.Reload(&updated); err == nil {
		t.Fatal("expected ipc_socket change to require a restart")
	}
	if got := c.Status().ServerURL; got != cfg.Client.ServerURL {
		t.Fatalf("failed reload changed live config to %q", got)
	}
}

func TestNewRejectsNonLoopbackPushListener(t *testing.T) {
	cfg := buildTestCfg(t, "https://sigil.example.com")
	cfg.Client.PushListen = ":9443"
	cfg.Client.PushToken = "0123456789abcdef0123456789abcdef"
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "client.push_listen") {
		t.Fatalf("expected non-loopback push listener to be rejected, got %v", err)
	}
}

func TestRunRejectsPushListenerChangedAfterNew(t *testing.T) {
	cfg := buildTestCfg(t, "https://sigil.example.com")
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Client.PushListen = ":9443"
	if err := c.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "client.push_listen") {
		t.Fatalf("expected mutated non-loopback push listener to be rejected, got %v", err)
	}
}

func TestPushHandlerRequiresBearerAndCoalescesPulls(t *testing.T) {
	var listRequests atomic.Int32
	release := make(chan struct{})
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("/v1/certificates", func(w http.ResponseWriter, _ *http.Request) {
		listRequests.Add(1)
		<-release
		_ = json.NewEncoder(w).Encode([]proto.CertSummary{})
	})
	apiMux.HandleFunc("/v1/heartbeat", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	apiServer := httptest.NewServer(apiMux)
	defer apiServer.Close()

	cfg := buildTestCfg(t, apiServer.URL)
	cfg.Client.PushToken = "0123456789abcdef0123456789abcdef"
	c := &Client{cfg: cfg, http: apiServer.Client()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pushServer := httptest.NewServer(c.pushHandler(ctx))
	defer pushServer.Close()

	unauthorized, err := http.Post(pushServer.URL+"/v1/push/notify", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d, want 401", unauthorized.StatusCode)
	}

	postAuthorized := func() *http.Response {
		req, err := http.NewRequest(http.MethodPost, pushServer.URL+"/v1/push/notify", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+cfg.Client.PushToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	first := postAuthorized()
	first.Body.Close()
	second := postAuthorized()
	second.Body.Close()
	if first.StatusCode != http.StatusAccepted || second.StatusCode != http.StatusAccepted {
		t.Fatalf("push statuses = %d, %d; want 202", first.StatusCode, second.StatusCode)
	}

	deadline := time.Now().Add(time.Second)
	for listRequests.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := listRequests.Load(); got != 1 {
		t.Fatalf("concurrent push notifications started %d pulls, want 1", got)
	}
	close(release)
}

func TestDiffCerts(t *testing.T) {
	summaries := []proto.CertSummary{
		{Name: "a", Fingerprint: "fp1"},
		{Name: "b", Fingerprint: "fp2"},
		{Name: "c", Fingerprint: "fp3"},
	}
	local := map[string]string{
		"a": "fp1", // same → no change
		"b": "fp9", // different → changed
		// c absent → new
	}
	changed := diffCerts(summaries, local)
	if len(changed) != 2 {
		t.Fatalf("expected 2 changed, got %d: %v", len(changed), changed)
	}
	names := map[string]bool{}
	for _, c := range changed {
		names[c.Name] = true
	}
	if !names["b"] || !names["c"] {
		t.Errorf("expected b and c to be changed, got %v", names)
	}
}

func TestSplitBundle(t *testing.T) {
	full := "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n" +
		"-----BEGIN CERTIFICATE-----\ninter\n-----END CERTIFICATE-----\n"
	b := &proto.CertBundle{FullchainPEM: full, KeyPEM: "key"}
	cb := splitBundle(b)

	if string(cb.CertPEM) != "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n" {
		t.Errorf("CertPEM: %q", cb.CertPEM)
	}
	if string(cb.ChainPEM) != "-----BEGIN CERTIFICATE-----\ninter\n-----END CERTIFICATE-----\n" {
		t.Errorf("ChainPEM: %q", cb.ChainPEM)
	}
	if string(cb.KeyPEM) != "key" {
		t.Errorf("KeyPEM: %q", cb.KeyPEM)
	}
}

func TestJitter(t *testing.T) {
	base := time.Hour
	pct := 0.1
	for i := 0; i < 100; i++ {
		got := jitter(base, pct)
		lo := base - time.Duration(float64(base)*pct) - time.Millisecond
		hi := base + time.Duration(float64(base)*pct) + time.Millisecond
		if got < lo || got > hi {
			t.Errorf("jitter out of range: %v not in [%v, %v]", got, lo, hi)
		}
	}
}
