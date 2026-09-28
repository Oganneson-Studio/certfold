package client

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
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/enroll"
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
	certPEM, err := authority.sign(name, publicKey, now, notAfter, serial)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM
}

// sign is issue for server handlers, which must not stop the test.
func (authority *testIdentityCA) sign(name string, publicKey any, now, notAfter time.Time, serial int64) (string, error) {
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
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

// serverTLSCertificate issues a certificate for the httptest listener address.
func (authority *testIdentityCA) serverTLSCertificate(t *testing.T, now time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "sigils"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, authority.cert, &key.PublicKey, authority.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// withSystemRoots stands in for the operating system trust store.
func withSystemRoots(t *testing.T, roots ...*x509.Certificate) {
	t.Helper()
	original := enroll.SystemCertPool
	enroll.SystemCertPool = func() (*x509.CertPool, error) {
		pool := x509.NewCertPool()
		for _, root := range roots {
			pool.AddCert(root)
		}
		return pool, nil
	}
	t.Cleanup(func() { enroll.SystemCertPool = original })
}

func privateKeyPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// newTestBundle returns new material for certificate name, as the bundle
// endpoint serves it: a self-signed certificate, its key and its fingerprint.
func newTestBundle(t *testing.T, name string) *proto.CertBundle {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name + ".example.test"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return &proto.CertBundle{
		Name:         name,
		Fingerprint:  "sha256:" + hex.EncodeToString(sum[:]),
		FullchainPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		KeyPEM:       privateKeyPEM(t, key),
	}
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
		Certificates: map[string]config.CertificateOutputs{},
	}
}

// fullchainOutput configures certificate name with one pem-fullchain output
// in dir and the on_change program argv, and returns the output's path.
func fullchainOutput(cfg *config.ClientConfig, dir, name string, argv ...string) string {
	path := filepath.Join(dir, name+".pem")
	cfg.Certificates[name] = config.CertificateOutputs{
		Outputs:  []config.OutputSpec{{Format: "pem-fullchain", Path: path}},
		OnChange: argv,
	}
	return path
}

func newTestClient(t *testing.T, cfg *config.ClientConfig) *Client {
	t.Helper()
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// seedStore writes a store that holds bundles, as an earlier run left it.
func seedStore(t *testing.T, dataDir string, bundles ...*proto.CertBundle) {
	t.Helper()
	certs := make(map[string]storedCert, len(bundles))
	for _, b := range bundles {
		certs[b.Name] = storedCert{Fingerprint: b.Fingerprint, FullchainPEM: b.FullchainPEM, KeyPEM: b.KeyPEM}
	}
	if err := saveStore(dataDir, certs); err != nil {
		t.Fatal(err)
	}
}

// readStore returns the store on disk.
func readStore(t *testing.T, dataDir string) map[string]storedCert {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dataDir, storeFileName))
	if err != nil {
		t.Fatal(err)
	}
	var file storeFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	return file.Certs
}

// fileContent returns the content of path, or "" if it cannot be read.
func fileContent(path string) string {
	data, _ := os.ReadFile(path)
	return string(data)
}

// setBackoff sets the backoff after a failed round for one test. Call it
// before startRun, so the loop has stopped when the cleanup restores it.
func setBackoff(t *testing.T, base, max time.Duration) {
	t.Helper()
	oldBase, oldMax := baseBackoff, maxBackoff
	baseBackoff, maxBackoff = base, max
	t.Cleanup(func() { baseBackoff, maxBackoff = oldBase, oldMax })
}

// waitFor polls cond until it holds, and fails the test if it does not hold
// within 10 seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// startRun runs c until the test ends. Start the servers c talks to before
// it: cleanups run in reverse order, and closing a server waits for the
// requests it is holding.
func startRun(t *testing.T, c *Client) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// fakeServer simulates the sigils HTTP API for client tests. GET /v1/sync
// works as on sigils: it answers 200 at once unless If-None-Match equals the
// current ETag, and otherwise waits until setView changes the view, maxWait
// passes (then it answers 304) or the client goes away.
type fakeServer struct {
	// maxWait and syncStatus are set before the server starts.
	maxWait time.Duration
	// syncStatus, when set, is called first for every sync request with its
	// If-None-Match; a non-zero result is answered as that status.
	syncStatus func(ifNoneMatch string) int

	mu           sync.Mutex
	bundles      map[string]*proto.CertBundle
	etag         string
	version      int
	changed      chan struct{}
	bundleStatus int
	syncs        []syncRecord
	answers      int
	bundleNames  []string
	heartbeats   int
}

// syncRecord is a sync request the fake server received.
type syncRecord struct {
	ifNoneMatch string
	at          time.Time
	// serial is the serial number of the client certificate, if any.
	serial string
}

// newFakeServer returns a fakeServer whose view holds bundles.
func newFakeServer(bundles ...*proto.CertBundle) *fakeServer {
	f := &fakeServer{maxWait: time.Minute, changed: make(chan struct{})}
	f.setView(bundles...)
	return f
}

// setView replaces the certificates served, which gives the view a new ETag
// even when they are the same, and wakes the sync requests waiting.
func (f *fakeServer) setView(bundles ...*proto.CertBundle) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bundles = make(map[string]*proto.CertBundle, len(bundles))
	for _, b := range bundles {
		f.bundles[b.Name] = b
	}
	f.version++
	f.etag = fmt.Sprintf(`"v%d"`, f.version)
	close(f.changed)
	f.changed = make(chan struct{})
}

func (f *fakeServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sync", f.sync)
	mux.HandleFunc("/v1/certificates/{name}/bundle", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		f.mu.Lock()
		f.bundleNames = append(f.bundleNames, name)
		bundle, status := f.bundles[name], f.bundleStatus
		f.mu.Unlock()
		if status != 0 {
			http.Error(w, http.StatusText(status), status)
			return
		}
		if bundle == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, bundle)
	})
	mux.HandleFunc("/v1/heartbeat", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		f.heartbeats++
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func (f *fakeServer) sync(w http.ResponseWriter, r *http.Request) {
	ifNoneMatch := r.Header.Get("If-None-Match")
	record := syncRecord{ifNoneMatch: ifNoneMatch, at: time.Now()}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		record.serial = r.TLS.PeerCertificates[0].SerialNumber.String()
	}
	f.mu.Lock()
	f.syncs = append(f.syncs, record)
	f.mu.Unlock()
	if f.syncStatus != nil {
		if status := f.syncStatus(ifNoneMatch); status != 0 {
			http.Error(w, http.StatusText(status), status)
			return
		}
	}

	timeout := time.NewTimer(f.maxWait)
	defer timeout.Stop()
	for {
		f.mu.Lock()
		etag, changed := f.etag, f.changed
		view := []proto.CertSummary{}
		for _, name := range slices.Sorted(maps.Keys(f.bundles)) {
			view = append(view, proto.CertSummary{Name: name, Fingerprint: f.bundles[name].Fingerprint})
		}
		f.mu.Unlock()
		if ifNoneMatch != etag {
			w.Header().Set("ETag", etag)
			writeJSON(w, view)
			f.answered()
			return
		}
		select {
		case <-changed:
		case <-timeout.C:
			w.Header().Set("ETag", etag)
			w.WriteHeader(http.StatusNotModified)
			f.answered()
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (f *fakeServer) answered() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers++
}

func (f *fakeServer) answerCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.answers
}

func (f *fakeServer) syncRequests() []syncRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.syncs)
}

// syncsWithETag returns how many sync requests carried If-None-Match.
func (f *fakeServer) syncsWithETag() int {
	n := 0
	for _, record := range f.syncRequests() {
		if record.ifNoneMatch != "" {
			n++
		}
	}
	return n
}

// syncAt waits for the sync request with index n and returns it. Tests find
// the request that follows an event by counting the requests before it: on
// Windows the clock may give both the same time.
func (f *fakeServer) syncAt(t *testing.T, n int) syncRecord {
	t.Helper()
	waitFor(t, fmt.Sprintf("sync request %d", n+1), func() bool { return len(f.syncRequests()) > n })
	return f.syncRequests()[n]
}

func (f *fakeServer) bundleRequests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.bundleNames)
}

func (f *fakeServer) heartbeatCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.heartbeats
}

// fakeHook stands in for runHook: it records the certificate of each run,
// which succeeds.
type fakeHook struct {
	mu   sync.Mutex
	runs []string
}

func (h *fakeHook) run(_ context.Context, certName string, _ []string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.runs = append(h.runs, certName)
	return nil
}

func (h *fakeHook) calls() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.runs)
}

// ---------------------------------------------------------------------------
// Fetch
// ---------------------------------------------------------------------------

func TestFetchWritesOutputsAndStore(t *testing.T) {
	bundle := newTestBundle(t, "api-prod")
	fs := newFakeServer(bundle)
	ts := httptest.NewServer(fs.handler())
	t.Cleanup(ts.Close)
	cfg := buildTestCfg(t, ts.URL)
	outPath := fullchainOutput(cfg, t.TempDir(), "api-prod")
	c := newTestClient(t, cfg)

	if err := c.Fetch(context.Background(), ""); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got := fileContent(outPath); got != bundle.FullchainPEM {
		t.Fatalf("output = %q, want the served fullchain", got)
	}
	stored := readStore(t, cfg.Client.DataDir)["api-prod"]
	if stored.Fingerprint != bundle.Fingerprint || stored.FullchainPEM != bundle.FullchainPEM || stored.KeyPEM != bundle.KeyPEM {
		t.Fatalf("stored = %+v, want the served bundle", stored)
	}
	status := c.Status()
	if !status.Online || status.LastPullAt.IsZero() || status.LastError != "" || status.Certs["api-prod"] != bundle.Fingerprint {
		t.Fatalf("status = %+v", status)
	}
	if got := fs.heartbeatCount(); got != 1 {
		t.Fatalf("heartbeats = %d, want 1", got)
	}
}

// TestFetchDoesNotRewriteUnchangedOutputs covers a pull without changes: the
// output file is left alone and on_change does not run again.
func TestFetchDoesNotRewriteUnchangedOutputs(t *testing.T) {
	bundle := newTestBundle(t, "api-prod")
	fs := newFakeServer(bundle)
	ts := httptest.NewServer(fs.handler())
	t.Cleanup(ts.Close)
	cfg := buildTestCfg(t, ts.URL)
	outPath := fullchainOutput(cfg, t.TempDir(), "api-prod", "/usr/sbin/reload")
	c := newTestClient(t, cfg)
	hooks := &fakeHook{}
	c.hook = hooks.run

	if err := c.Fetch(context.Background(), ""); err != nil {
		t.Fatalf("first Fetch: %v", err)
	}
	before, err := os.Stat(outPath)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if err := c.Fetch(context.Background(), ""); err != nil {
		t.Fatalf("second Fetch: %v", err)
	}
	after, err := os.Stat(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("the unchanged output was rewritten")
	}
	if got := fs.bundleRequests(); !slices.Equal(got, []string{"api-prod"}) {
		t.Fatalf("bundle requests = %v, want one for api-prod", got)
	}
	if got := hooks.calls(); !slices.Equal(got, []string{"api-prod"}) {
		t.Fatalf("on_change runs = %v, want one after the first fetch", got)
	}
}

// TestFetchStoresCertificatesWithoutOutputs covers a subscribed certificate
// client.yaml has no outputs for: its material is only stored, and nothing
// is written to a path derived from its name.
func TestFetchStoresCertificatesWithoutOutputs(t *testing.T) {
	bundle := newTestBundle(t, "tls-internal")
	ts := httptest.NewServer(newFakeServer(bundle).handler())
	t.Cleanup(ts.Close)
	cfg := buildTestCfg(t, ts.URL)
	c := newTestClient(t, cfg)

	if err := c.Fetch(context.Background(), ""); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got := c.Status().Certs["tls-internal"]; got != bundle.Fingerprint {
		t.Fatalf("status fingerprint = %q, want %q", got, bundle.Fingerprint)
	}
	entries, err := os.ReadDir(cfg.Client.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if !slices.Equal(names, []string{storeFileName}) {
		t.Fatalf("data_dir holds %v, want only %s", names, storeFileName)
	}
}

func TestFetchReportsServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	t.Cleanup(ts.Close)
	c := newTestClient(t, buildTestCfg(t, ts.URL))

	err := c.Fetch(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("Fetch error = %v, want the server's 500", err)
	}
	if status := c.Status(); status.Online || status.LastError != err.Error() {
		t.Fatalf("status = %+v", status)
	}
}

// TestFetchTrustsSystemRootsAndMiniCA covers a server that presents a publicly
// trusted server.tls_cert_file: pulls must trust the system roots, as
// enrollment does, while the mini-CA keeps authenticating the client.
func TestFetchTrustsSystemRootsAndMiniCA(t *testing.T) {
	now := time.Now()
	miniCA := newTestIdentityCA(t, now)
	publicCA := newTestIdentityCA(t, now)
	unrelatedCA := newTestIdentityCA(t, now)
	withSystemRoots(t, publicCA.cert)

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientCert := miniCA.issue(t, "web-1", &clientKey.PublicKey, now, now.Add(90*24*time.Hour), 2)
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(miniCA.cert)

	for _, tc := range []struct {
		name    string
		issuer  *testIdentityCA
		trusted bool
	}{
		{name: "public CA in system roots", issuer: publicCA, trusted: true},
		{name: "mini-CA", issuer: miniCA, trusted: true},
		{name: "unrelated CA", issuer: unrelatedCA, trusted: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewUnstartedServer(newFakeServer().handler())
			ts.TLS = &tls.Config{
				Certificates: []tls.Certificate{tc.issuer.serverTLSCertificate(t, now)},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    clientCAs,
			}
			ts.StartTLS()
			defer ts.Close()

			cfg := buildTestCfg(t, ts.URL)
			cfg.Identity = config.IdentitySection{
				CACert:     miniCA.certPEM,
				ClientCert: clientCert,
				ClientKey:  privateKeyPEM(t, clientKey),
			}
			c, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			err = c.Fetch(context.Background(), "")
			if tc.trusted {
				if err != nil {
					t.Fatalf("Fetch: %v", err)
				}
				return
			}
			var unknownAuthority x509.UnknownAuthorityError
			if !errors.As(err, &unknownAuthority) {
				t.Fatalf("Fetch error = %v, want an unknown authority error", err)
			}
		})
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

// TestFetchNamedCertificateForcesOnlyThatBundle covers sigilc fetch --cert:
// it downloads the named certificate again, and only it, but unchanged
// material neither rewrites outputs nor runs on_change.
func TestFetchNamedCertificateForcesOnlyThatBundle(t *testing.T) {
	a, b := newTestBundle(t, "a"), newTestBundle(t, "b")
	fs := newFakeServer(a, b)
	ts := httptest.NewServer(fs.handler())
	t.Cleanup(ts.Close)
	cfg := buildTestCfg(t, ts.URL)
	dir := t.TempDir()
	fullchainOutput(cfg, dir, "a", "/usr/sbin/reload")
	fullchainOutput(cfg, dir, "b", "/usr/sbin/reload")
	c := newTestClient(t, cfg)
	hooks := &fakeHook{}
	c.hook = hooks.run
	if err := c.Fetch(context.Background(), ""); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	downloaded, ran := len(fs.bundleRequests()), len(hooks.calls())

	if err := c.Fetch(context.Background(), "b"); err != nil {
		t.Fatalf("Fetch b: %v", err)
	}
	if got := fs.bundleRequests()[downloaded:]; !slices.Equal(got, []string{"b"}) {
		t.Fatalf("bundle requests of the named fetch = %v, want only b", got)
	}
	if got := hooks.calls()[ran:]; len(got) != 0 {
		t.Fatalf("the named fetch of unchanged material ran on_change for %v", got)
	}
	if readStore(t, cfg.Client.DataDir)["b"].HookPending {
		t.Fatal("the named fetch of unchanged material set hook_pending")
	}

	err := c.Fetch(context.Background(), "missing")
	if err == nil || !strings.Contains(err.Error(), `certificate "missing" is not subscribed`) {
		t.Fatalf("Fetch missing = %v, want a not subscribed error", err)
	}
}

// TestFetchRejectsBadBundle covers bundles that must not replace the stored
// material: the outputs keep the old certificate and the error is reported.
func TestFetchRejectsBadBundle(t *testing.T) {
	for _, tc := range []struct {
		name string
		bad  func(t *testing.T, renewed proto.CertBundle) proto.CertBundle
	}{
		{name: "key of another certificate", bad: func(t *testing.T, renewed proto.CertBundle) proto.CertBundle {
			renewed.KeyPEM = newTestBundle(t, "api-prod").KeyPEM
			return renewed
		}},
		{name: "another certificate's name", bad: func(_ *testing.T, renewed proto.CertBundle) proto.CertBundle {
			renewed.Name = "api-stage"
			return renewed
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := newTestBundle(t, "api-prod")
			fs := newFakeServer(old)
			var serveBad atomic.Bool
			var bad proto.CertBundle
			api := fs.handler()
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if serveBad.Load() && r.URL.Path == "/v1/certificates/api-prod/bundle" {
					writeJSON(w, bad)
					return
				}
				api.ServeHTTP(w, r)
			}))
			t.Cleanup(ts.Close)
			cfg := buildTestCfg(t, ts.URL)
			outPath := fullchainOutput(cfg, t.TempDir(), "api-prod")
			c := newTestClient(t, cfg)
			if err := c.Fetch(context.Background(), ""); err != nil {
				t.Fatalf("Fetch: %v", err)
			}

			renewed := newTestBundle(t, "api-prod")
			bad = tc.bad(t, *renewed)
			serveBad.Store(true)
			fs.setView(renewed)
			err := c.Fetch(context.Background(), "")
			if err == nil || !strings.Contains(err.Error(), "bundle api-prod") {
				t.Fatalf("Fetch error = %v, want the bad bundle reported", err)
			}
			if got := readStore(t, cfg.Client.DataDir)["api-prod"].Fingerprint; got != old.Fingerprint {
				t.Fatalf("stored fingerprint = %q, want the old %q", got, old.Fingerprint)
			}
			if got := fileContent(outPath); got != old.FullchainPEM {
				t.Fatal("the bad bundle replaced the output")
			}
			if status := c.Status(); status.LastError != err.Error() || status.Certs["api-prod"] != old.Fingerprint {
				t.Fatalf("status = %+v", status)
			}
		})
	}
}

// TestReconcileFailureSkipsHook covers a certificate whose outputs cannot all
// be written: its on_change program waits, with hook_pending on disk, until
// they are complete.
func TestReconcileFailureSkipsHook(t *testing.T) {
	bundle := newTestBundle(t, "api-prod")
	ts := httptest.NewServer(newFakeServer(bundle).handler())
	t.Cleanup(ts.Close)
	dir := t.TempDir()
	// A file where the key's directory belongs fails that output.
	blocker := filepath.Join(dir, "keys")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(blocker, "api.key")
	cfg := buildTestCfg(t, ts.URL)
	cfg.Certificates["api-prod"] = config.CertificateOutputs{
		Outputs: []config.OutputSpec{
			{Format: "pem-fullchain", Path: filepath.Join(dir, "api.pem")},
			{Format: "pem-key", Path: keyPath},
		},
		OnChange: []string{"/usr/sbin/reload"},
	}
	c := newTestClient(t, cfg)
	hooks := &fakeHook{}
	c.hook = hooks.run

	if err := c.Fetch(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "outputs of certificate api-prod") {
		t.Fatalf("Fetch error = %v, want the failed output reported", err)
	}
	if got := hooks.calls(); len(got) != 0 {
		t.Fatalf("on_change ran for %v with an output missing", got)
	}
	if !readStore(t, cfg.Client.DataDir)["api-prod"].HookPending {
		t.Fatal("hook_pending of the new material is not on disk")
	}

	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	if err := c.Fetch(context.Background(), ""); err != nil {
		t.Fatalf("Fetch after the repair: %v", err)
	}
	if got := fileContent(keyPath); got != bundle.KeyPEM {
		t.Fatal("the failed output was not written after the repair")
	}
	if got := hooks.calls(); !slices.Equal(got, []string{"api-prod"}) {
		t.Fatalf("on_change runs = %v, want one after the repair", got)
	}
	if readStore(t, cfg.Client.DataDir)["api-prod"].HookPending {
		t.Fatal("hook_pending stayed set after on_change succeeded")
	}
}

// TestCertificateLeavingViewKeepsOutputs covers a certificate the server no
// longer lists for the client: it leaves the store, and its outputs and
// on_change program are left alone.
func TestCertificateLeavingViewKeepsOutputs(t *testing.T) {
	a, b := newTestBundle(t, "a"), newTestBundle(t, "b")
	fs := newFakeServer(a, b)
	ts := httptest.NewServer(fs.handler())
	t.Cleanup(ts.Close)
	cfg := buildTestCfg(t, ts.URL)
	dir := t.TempDir()
	fullchainOutput(cfg, dir, "a")
	pathB := fullchainOutput(cfg, dir, "b", "/usr/sbin/reload")
	c := newTestClient(t, cfg)
	hooks := &fakeHook{}
	c.hook = hooks.run
	if err := c.Fetch(context.Background(), ""); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	before, err := os.Stat(pathB)
	if err != nil {
		t.Fatal(err)
	}
	ran := len(hooks.calls())

	fs.setView(a)
	if err := c.Fetch(context.Background(), ""); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if _, ok := readStore(t, cfg.Client.DataDir)["b"]; ok {
		t.Fatal("b stayed in the store after leaving the view")
	}
	if _, ok := c.Status().Certs["b"]; ok {
		t.Fatal("status still lists b")
	}
	after, err := os.Stat(pathB)
	if err != nil {
		t.Fatalf("b's output is gone: %v", err)
	}
	if !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) || fileContent(pathB) != b.FullchainPEM {
		t.Fatal("b's output changed after b left the view")
	}
	if got := hooks.calls()[ran:]; len(got) != 0 {
		t.Fatalf("on_change ran for %v after b left the view", got)
	}
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

func TestStoreIsPrivate(t *testing.T) {
	t.Run("written", func(t *testing.T) {
		ts := httptest.NewServer(newFakeServer(newTestBundle(t, "api-prod")).handler())
		t.Cleanup(ts.Close)
		cfg := buildTestCfg(t, ts.URL)
		cfg.Client.DataDir = usersReadableDir(t)
		if err := newTestClient(t, cfg).Fetch(context.Background(), ""); err != nil {
			t.Fatalf("Fetch: %v", err)
		}
		checkPrivate(t, filepath.Join(cfg.Client.DataDir, storeFileName))
	})
	t.Run("existing", func(t *testing.T) {
		cfg := buildTestCfg(t, "https://sigil.example.test")
		cfg.Client.DataDir = usersReadableDir(t)
		path := filepath.Join(cfg.Client.DataDir, storeFileName)
		if err := os.WriteFile(path, []byte(`{"certs":{}}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		newTestClient(t, cfg)
		checkPrivate(t, path)
	})
}

func TestStoreSurvivesRestart(t *testing.T) {
	bundle := newTestBundle(t, "api-prod")
	ts := httptest.NewServer(newFakeServer(bundle).handler())
	t.Cleanup(ts.Close)
	cfg := buildTestCfg(t, ts.URL)
	c := newTestClient(t, cfg)
	if err := c.Fetch(context.Background(), ""); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	restarted := newTestClient(t, cfg)
	if got, want := restarted.store["api-prod"], c.store["api-prod"]; got != want || got.Fingerprint != bundle.Fingerprint {
		t.Fatalf("store after restart = %+v, want %+v", got, want)
	}
	if got := restarted.Status().Certs["api-prod"]; got != bundle.Fingerprint {
		t.Fatalf("status fingerprint after restart = %q, want %q", got, bundle.Fingerprint)
	}
}

func TestCorruptStoreIsFetchedAgain(t *testing.T) {
	bundle := newTestBundle(t, "api-prod")
	fs := newFakeServer(bundle)
	ts := httptest.NewServer(fs.handler())
	t.Cleanup(ts.Close)
	cfg := buildTestCfg(t, ts.URL)
	outPath := fullchainOutput(cfg, t.TempDir(), "api-prod")
	if err := os.WriteFile(filepath.Join(cfg.Client.DataDir, storeFileName), []byte(`{"certs":`), 0o600); err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, cfg)
	if got := c.Status().Certs; len(got) != 0 {
		t.Fatalf("certificates read from a corrupt store: %v", got)
	}

	if err := c.Fetch(context.Background(), ""); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got := fs.bundleRequests(); !slices.Equal(got, []string{"api-prod"}) {
		t.Fatalf("bundle requests = %v, want api-prod again", got)
	}
	if got := fileContent(outPath); got != bundle.FullchainPEM {
		t.Fatal("output not written after the corrupt store")
	}
	if got := readStore(t, cfg.Client.DataDir)["api-prod"].Fingerprint; got != bundle.Fingerprint {
		t.Fatalf("stored fingerprint = %q, want %q", got, bundle.Fingerprint)
	}
}

// ---------------------------------------------------------------------------
// Sync loop
// ---------------------------------------------------------------------------

// TestRunRestoresOutputsBeforeFirstAnswer covers a restart while the server is
// unavailable: the server answers 503 only once the client gives up, so only
// the reconcile at startup can bring the deleted output back.
func TestRunRestoresOutputsBeforeFirstAnswer(t *testing.T) {
	bundle := newTestBundle(t, "api-prod")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(ts.Close)
	cfg := buildTestCfg(t, ts.URL)
	outPath := fullchainOutput(cfg, t.TempDir(), "api-prod")
	seedStore(t, cfg.Client.DataDir, bundle)
	c := newTestClient(t, cfg)

	startRun(t, c)
	waitFor(t, "the output restored from the store", func() bool { return fileContent(outPath) == bundle.FullchainPEM })
}

// TestRoundReconcilesAfterNotModified covers an output deleted while nothing
// changes on the server: a round that gets 304 brings it back from the store.
func TestRoundReconcilesAfterNotModified(t *testing.T) {
	bundle := newTestBundle(t, "api-prod")
	fs := newFakeServer(bundle)
	fs.maxWait = 20 * time.Millisecond
	ts := httptest.NewServer(fs.handler())
	t.Cleanup(ts.Close)
	cfg := buildTestCfg(t, ts.URL)
	outPath := fullchainOutput(cfg, t.TempDir(), "api-prod")
	seedStore(t, cfg.Client.DataDir, bundle)
	c := newTestClient(t, cfg)

	startRun(t, c)
	waitFor(t, "a round answered 304", func() bool { return fs.syncsWithETag() >= 2 })
	if err := os.Remove(outPath); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the deleted output restored", func() bool { return fileContent(outPath) == bundle.FullchainPEM })
	if got := fs.bundleRequests(); len(got) != 0 {
		t.Fatalf("bundle requests = %v, want none", got)
	}
}

// TestRoundReconcilesAfterError covers an output deleted while the server
// fails: the rounds that back off still bring it back.
func TestRoundReconcilesAfterError(t *testing.T) {
	setBackoff(t, 20*time.Millisecond, 50*time.Millisecond)
	bundle := newTestBundle(t, "api-prod")
	fs := newFakeServer(bundle)
	fs.syncStatus = func(string) int { return http.StatusServiceUnavailable }
	ts := httptest.NewServer(fs.handler())
	t.Cleanup(ts.Close)
	cfg := buildTestCfg(t, ts.URL)
	outPath := fullchainOutput(cfg, t.TempDir(), "api-prod")
	seedStore(t, cfg.Client.DataDir, bundle)
	c := newTestClient(t, cfg)

	startRun(t, c)
	waitFor(t, "two failed rounds", func() bool { return len(fs.syncRequests()) >= 2 })
	if err := os.Remove(outPath); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the deleted output restored", func() bool { return fileContent(outPath) == bundle.FullchainPEM })
	if status := c.Status(); status.Online || !strings.Contains(status.LastError, "503") {
		t.Fatalf("status = %+v, want the 503 reported", status)
	}
}

// TestRunHasNoPeriodicPull checks that pull_interval no longer starts full
// pulls: after the first one, every request waits with the view's ETag.
func TestRunHasNoPeriodicPull(t *testing.T) {
	fs := newFakeServer(newTestBundle(t, "api-prod"))
	fs.maxWait = 20 * time.Millisecond
	ts := httptest.NewServer(fs.handler())
	t.Cleanup(ts.Close)
	cfg := buildTestCfg(t, ts.URL)
	cfg.Client.PullInterval = 10 * time.Millisecond
	c := newTestClient(t, cfg)

	startRun(t, c)
	waitFor(t, "ten rounds", func() bool { return fs.syncsWithETag() >= 10 })
	full := 0
	for _, record := range fs.syncRequests() {
		if record.ifNoneMatch == "" {
			full++
		}
	}
	if full != 1 {
		t.Fatalf("%d sync requests without If-None-Match, want only the first", full)
	}
}

// TestSyncDeliversChangeWhileWaiting covers the server answering a held
// request because the client's view changed.
func TestSyncDeliversChangeWhileWaiting(t *testing.T) {
	old := newTestBundle(t, "api-prod")
	fs := newFakeServer(old)
	ts := httptest.NewServer(fs.handler())
	t.Cleanup(ts.Close)
	cfg := buildTestCfg(t, ts.URL)
	outPath := fullchainOutput(cfg, t.TempDir(), "api-prod")
	c := newTestClient(t, cfg)

	startRun(t, c)
	waitFor(t, "the loop to wait for a change", func() bool {
		return fs.syncsWithETag() >= 1 && fileContent(outPath) == old.FullchainPEM
	})
	renewed := newTestBundle(t, "api-prod")
	fs.setView(renewed)
	waitFor(t, "the renewed certificate written", func() bool { return fileContent(outPath) == renewed.FullchainPEM })
	if got := c.Status().Certs["api-prod"]; got != renewed.Fingerprint {
		t.Fatalf("status fingerprint = %q, want %q", got, renewed.Fingerprint)
	}
}

func TestSyncSendsETagOfAppliedView(t *testing.T) {
	fs := newFakeServer(newTestBundle(t, "api-prod"))
	ts := httptest.NewServer(fs.handler())
	t.Cleanup(ts.Close)
	c := newTestClient(t, buildTestCfg(t, ts.URL))

	startRun(t, c)
	waitFor(t, "two sync requests", func() bool { return len(fs.syncRequests()) >= 2 })
	syncs := fs.syncRequests()
	if syncs[0].ifNoneMatch != "" || syncs[1].ifNoneMatch != `"v1"` {
		t.Fatalf("If-None-Match of the first two requests = %q, %q; want none, then \"v1\"",
			syncs[0].ifNoneMatch, syncs[1].ifNoneMatch)
	}
}

// TestFailedViewIsRequestedAgain covers a view that could not be applied: the
// etag does not advance, so the next round asks for the whole view again,
// after the backoff.
func TestFailedViewIsRequestedAgain(t *testing.T) {
	setBackoff(t, 500*time.Millisecond, 500*time.Millisecond)
	fs := newFakeServer(newTestBundle(t, "api-prod"))
	fs.bundleStatus = http.StatusServiceUnavailable
	ts := httptest.NewServer(fs.handler())
	t.Cleanup(ts.Close)
	c := newTestClient(t, buildTestCfg(t, ts.URL))

	startRun(t, c)
	waitFor(t, "two sync requests", func() bool { return len(fs.syncRequests()) >= 2 })
	syncs := fs.syncRequests()
	if syncs[1].ifNoneMatch != "" {
		t.Fatalf("the request after a failed view carried If-None-Match %q", syncs[1].ifNoneMatch)
	}
	if gap := syncs[1].at.Sub(syncs[0].at); gap < 400*time.Millisecond {
		t.Fatalf("the round after a failed view started after %v, want the 500ms backoff", gap)
	}
}

// TestSyncOutlastsHTTPTimeout checks that the loop's held requests do not use
// the HTTP client's timeout, which is shorter than the server's wait.
func TestSyncOutlastsHTTPTimeout(t *testing.T) {
	oldTimeout := httpTimeout
	httpTimeout = 100 * time.Millisecond
	t.Cleanup(func() { httpTimeout = oldTimeout })
	fs := newFakeServer()
	fs.maxWait = 300 * time.Millisecond
	ts := httptest.NewServer(fs.handler())
	t.Cleanup(ts.Close)
	c := newTestClient(t, buildTestCfg(t, ts.URL))

	startRun(t, c)
	waitFor(t, "three held requests", func() bool { return fs.syncsWithETag() >= 3 })
	if status := c.Status(); !status.Online || status.LastError != "" {
		t.Fatalf("status = %+v, want a successful round", status)
	}
}

// TestHookFailureBacksOffUntilItSucceeds covers an on_change program that
// fails: hook_pending is on disk before it runs, a round that runs it and
// fails backs off, and the next round runs it again until it succeeds.
func TestHookFailureBacksOffUntilItSucceeds(t *testing.T) {
	setBackoff(t, time.Second, time.Second)
	bundle := newTestBundle(t, "api-prod")
	fs := newFakeServer(bundle)
	fs.maxWait = 20 * time.Millisecond
	ts := httptest.NewServer(fs.handler())
	t.Cleanup(ts.Close)
	cfg := buildTestCfg(t, ts.URL)
	fullchainOutput(cfg, t.TempDir(), "api-prod", "/usr/sbin/reload")
	// The output is missing, so the reconcile at startup writes it and sets
	// hook_pending.
	seedStore(t, cfg.Client.DataDir, bundle)
	c := newTestClient(t, cfg)

	type hookRun struct {
		end           time.Time
		pendingOnDisk bool
		syncsBefore   int
	}
	var mu sync.Mutex
	var runs []hookRun
	storePath := filepath.Join(cfg.Client.DataDir, storeFileName)
	c.hook = func(_ context.Context, certName string, _ []string) error {
		var disk storeFile
		data, _ := os.ReadFile(storePath)
		_ = json.Unmarshal(data, &disk)
		mu.Lock()
		defer mu.Unlock()
		// The runs at startup and in the first round fail.
		fail := len(runs) < 2
		runs = append(runs, hookRun{
			end:           time.Now(),
			pendingOnDisk: disk.Certs[certName].HookPending,
			syncsBefore:   len(fs.syncRequests()),
		})
		if fail {
			return fmt.Errorf("on_change of %s exited with status 1", certName)
		}
		return nil
	}
	hookRuns := func() []hookRun {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(runs)
	}

	startRun(t, c)
	waitFor(t, "three runs of on_change", func() bool { return len(hookRuns()) >= 3 })
	got := hookRuns()
	if !got[0].pendingOnDisk {
		t.Fatal("hook_pending was not on disk when on_change ran")
	}
	if gap := fs.syncAt(t, got[1].syncsBefore).at.Sub(got[1].end); gap < 800*time.Millisecond {
		t.Fatalf("the round after a failed on_change started after %v, want the 1s backoff", gap)
	}
	if gap := fs.syncAt(t, got[2].syncsBefore).at.Sub(got[2].end); gap > 500*time.Millisecond {
		t.Fatalf("the round after on_change succeeded started after %v, want no backoff", gap)
	}
	if readStore(t, cfg.Client.DataDir)["api-prod"].HookPending {
		t.Fatal("hook_pending stayed set after on_change succeeded")
	}
	if status := c.Status(); status.LastError != "" {
		t.Fatalf("last error = %q after on_change succeeded", status.LastError)
	}
}

// TestReloadReconcilesAndRestartsSync covers sigilc reload: the outputs of the
// new configuration exist when Reload returns, and the loop pulls the whole
// view at once, whether it was waiting for an answer or backing off.
func TestReloadReconcilesAndRestartsSync(t *testing.T) {
	t.Run("waiting for an answer", func(t *testing.T) {
		bundle := newTestBundle(t, "api-prod")
		fs := newFakeServer(bundle)
		ts := httptest.NewServer(fs.handler())
		t.Cleanup(ts.Close)
		cfg := buildTestCfg(t, ts.URL)
		dir := t.TempDir()
		firstPath := fullchainOutput(cfg, dir, "api-prod")
		c := newTestClient(t, cfg)
		startRun(t, c)
		waitFor(t, "the loop to wait for a change", func() bool { return fs.syncsWithETag() >= 1 })

		updated := *cfg
		addedPath := filepath.Join(dir, "added.pem")
		updated.Certificates = map[string]config.CertificateOutputs{"api-prod": {Outputs: []config.OutputSpec{
			{Format: "pem-fullchain", Path: firstPath},
			{Format: "pem-fullchain", Path: addedPath},
		}}}
		n := len(fs.syncRequests())
		reloadedAt := time.Now()
		if err := c.Reload(&updated); err != nil {
			t.Fatalf("Reload: %v", err)
		}
		if got := fileContent(addedPath); got != bundle.FullchainPEM {
			t.Fatal("Reload returned before writing the added output")
		}
		next := fs.syncAt(t, n)
		if next.ifNoneMatch != "" {
			t.Fatalf("the request after Reload carried If-None-Match %q", next.ifNoneMatch)
		}
		t.Logf("full pull %v after Reload", next.at.Sub(reloadedAt))
	})

	t.Run("backing off", func(t *testing.T) {
		setBackoff(t, time.Minute, time.Minute)
		fs := newFakeServer(newTestBundle(t, "api-prod"))
		fs.syncStatus = func(ifNoneMatch string) int {
			if ifNoneMatch != "" {
				return http.StatusServiceUnavailable
			}
			return 0
		}
		ts := httptest.NewServer(fs.handler())
		t.Cleanup(ts.Close)
		cfg := buildTestCfg(t, ts.URL)
		c := newTestClient(t, cfg)
		startRun(t, c)
		waitFor(t, "a failed round", func() bool { return fs.syncsWithETag() >= 1 })

		n := len(fs.syncRequests())
		reloadedAt := time.Now()
		updated := *cfg
		if err := c.Reload(&updated); err != nil {
			t.Fatalf("Reload: %v", err)
		}
		next := fs.syncAt(t, n)
		if next.ifNoneMatch != "" {
			t.Fatalf("the request after Reload carried If-None-Match %q", next.ifNoneMatch)
		}
		t.Logf("full pull %v after Reload", next.at.Sub(reloadedAt))
	})
}

// TestReloadDiscardsAnswerThatArrivedDuringReload covers an answer to the
// loop's request that arrives while Reload holds pullMu: the request was made
// with the old configuration, so the loop must drop the answer rather than
// apply it and set the etag Reload cleared.
func TestReloadDiscardsAnswerThatArrivedDuringReload(t *testing.T) {
	bundle := newTestBundle(t, "api-prod")
	fs := newFakeServer(bundle)
	ts := httptest.NewServer(fs.handler())
	t.Cleanup(ts.Close)
	cfg := buildTestCfg(t, ts.URL)
	dir := t.TempDir()
	firstPath := fullchainOutput(cfg, dir, "api-prod")
	c := newTestClient(t, cfg)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	c.hook = func(context.Context, string, []string) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return nil
	}
	startRun(t, c)
	// Registered after startRun, so it runs first: stopping Run waits for
	// pullMu, which Reload holds while the program waits.
	t.Cleanup(unblock)
	waitFor(t, "the loop to wait for a change", func() bool { return fs.syncsWithETag() >= 1 })

	// The reloaded configuration adds an output and an on_change program, so
	// Reload's reconcile runs the program, which waits for the test.
	updated := *cfg
	updated.Certificates = map[string]config.CertificateOutputs{"api-prod": {
		Outputs: []config.OutputSpec{
			{Format: "pem-fullchain", Path: firstPath},
			{Format: "pem-fullchain", Path: filepath.Join(dir, "added.pem")},
		},
		OnChange: []string{"/usr/sbin/reload"},
	}}
	reloaded := make(chan error, 1)
	go func() { reloaded <- c.Reload(&updated) }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("Reload did not run on_change")
	}

	// The view changes, so the server answers the loop's request, which then
	// waits for pullMu.
	answers := fs.answerCount()
	fs.setView(bundle)
	waitFor(t, "the answer to the loop's request", func() bool { return fs.answerCount() > answers })
	time.Sleep(200 * time.Millisecond) // let the client read the answer
	n := len(fs.syncRequests())
	unblock()
	select {
	case err := <-reloaded:
		if err != nil {
			t.Fatalf("Reload: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Reload did not return")
	}

	waitFor(t, "the request after Reload", func() bool { return len(fs.syncRequests()) > n })
	if next := fs.syncRequests()[n]; next.ifNoneMatch != "" {
		t.Fatalf("the request after Reload carried If-None-Match %q: the loop applied an answer to the old configuration", next.ifNoneMatch)
	}
}

// TestIdentitySwitchRestartsSync covers an identity renewed while the loop
// waits for an answer: the request presenting the old identity is cancelled,
// and the next one presents the new identity with the same ETag.
func TestIdentitySwitchRestartsSync(t *testing.T) {
	now := time.Now()
	authority := newTestIdentityCA(t, now)
	fs := newFakeServer()
	mux := http.NewServeMux()
	mux.Handle("/", fs.handler())
	mux.HandleFunc("/v1/identity/renew", func(w http.ResponseWriter, r *http.Request) {
		var req proto.RenewIdentityRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		block, _ := pem.Decode([]byte(req.CSR))
		if block == nil {
			http.Error(w, "no CSR PEM", http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		certPEM, err := authority.sign("web-1", csr.PublicKey, now, now.Add(90*24*time.Hour), 3)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, proto.RenewIdentityResponse{ClientCert: certPEM})
	})
	ts := httptest.NewUnstartedServer(mux)
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(authority.cert)
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{authority.serverTLSCertificate(t, now)},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)

	oldKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := buildTestCfg(t, ts.URL)
	cfg.Client.IdentityRenewBefore = 30 * 24 * time.Hour
	cfg.Identity = config.IdentitySection{
		CACert:     authority.certPEM,
		ClientCert: authority.issue(t, "web-1", &oldKey.PublicKey, now, now.Add(60*24*time.Hour), 2),
		ClientKey:  privateKeyPEM(t, oldKey),
	}
	c, err := New(cfg, WithIdentitySaver(func(string, string, string) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	// Moving the clock 31 days ahead makes the identity due for renewal.
	var ahead atomic.Int64
	c.now = func() time.Time { return time.Now().Add(time.Duration(ahead.Load())) }
	startRun(t, c)
	waitFor(t, "the loop to wait for a change", func() bool { return fs.syncsWithETag() >= 1 })
	syncs := fs.syncRequests()
	held := syncs[len(syncs)-1]
	if held.serial != "2" {
		t.Fatalf("the held request presented serial %s, want the old identity 2", held.serial)
	}

	ahead.Store(int64(31 * 24 * time.Hour))
	c.pullMu.Lock()
	err = c.renewIdentityLocked(context.Background())
	c.pullMu.Unlock()
	if err != nil {
		t.Fatalf("renew identity: %v", err)
	}
	next := fs.syncAt(t, len(syncs))
	if next.serial != "3" {
		t.Fatalf("the request after the switch presented serial %s, want the new identity 3", next.serial)
	}
	if next.ifNoneMatch != held.ifNoneMatch {
		t.Fatalf("the request after the switch carried If-None-Match %q, want %q", next.ifNoneMatch, held.ifNoneMatch)
	}
}

// TestFetchDoesNotWaitForHeldSync checks that the loop waits for the server's
// answer without pullMu: an IPC fetch meanwhile completes at once.
func TestFetchDoesNotWaitForHeldSync(t *testing.T) {
	fs := newFakeServer()
	ts := httptest.NewServer(fs.handler())
	t.Cleanup(ts.Close)
	c := newTestClient(t, buildTestCfg(t, ts.URL))
	startRun(t, c)
	waitFor(t, "the loop to wait for a change", func() bool { return fs.syncsWithETag() >= 1 })

	fetched := make(chan error, 1)
	go func() { fetched <- c.Fetch(context.Background(), "") }()
	select {
	case err := <-fetched:
		if err != nil {
			t.Fatalf("Fetch: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Fetch waited for the loop's held request")
	}
}

// TestRunWaitsForInFlightPull covers a pull started by IPC or push that is
// still running when the daemon stops.
func TestRunWaitsForInFlightPull(t *testing.T) {
	var blockNext atomic.Bool
	blocked := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	fs := newFakeServer()
	fs.syncStatus = func(ifNoneMatch string) int {
		if ifNoneMatch == "" && blockNext.CompareAndSwap(true, false) {
			close(blocked)
			<-release
		}
		return 0
	}
	ts := httptest.NewServer(fs.handler())
	t.Cleanup(ts.Close)
	// Close waits for the blocked handler, so release it on every exit path.
	t.Cleanup(unblock)

	c := newTestClient(t, buildTestCfg(t, ts.URL))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	waitFor(t, "the loop to wait for a change", func() bool { return fs.syncsWithETag() >= 1 })

	blockNext.Store(true)
	fetched := make(chan error, 1)
	go func() { fetched <- c.Fetch(context.Background(), "") }()
	select {
	case <-blocked:
	case <-time.After(10 * time.Second):
		t.Fatal("Fetch did not reach the blocked sync request")
	}
	cancel()
	select {
	case <-done:
		t.Fatal("Run returned while a pull was still running")
	case <-time.After(100 * time.Millisecond):
	}

	unblock()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after the pull finished")
	}
	if err := <-fetched; err != nil {
		t.Fatalf("Fetch: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Reload
// ---------------------------------------------------------------------------

func TestReloadAppliesRuntimeConfig(t *testing.T) {
	cfg := buildTestCfg(t, "https://old.example.com")
	c := newTestClient(t, cfg)
	updated := buildTestCfg(t, "https://new.example.com")
	updated.Client.Name = "web-2"
	updated.Client.DataDir = cfg.Client.DataDir
	if err := c.Reload(updated); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	status := c.Status()
	if status.Name != "web-2" || status.ServerURL != "https://new.example.com" {
		t.Fatalf("status after reload = %+v", status)
	}
}

func TestReloadRejectsRestartOnlyChanges(t *testing.T) {
	for _, tc := range []struct {
		field  string
		change func(*config.ClientSection)
	}{
		{field: "client.ipc_socket", change: func(s *config.ClientSection) { s.IPCSocket = "changed.sock" }},
		{field: "client.data_dir", change: func(s *config.ClientSection) { s.DataDir = filepath.Join(s.DataDir, "moved") }},
	} {
		t.Run(tc.field, func(t *testing.T) {
			cfg := buildTestCfg(t, "https://sigil.example.com")
			c := newTestClient(t, cfg)
			updated := *cfg
			updated.Client.ServerURL = "https://new.example.com"
			tc.change(&updated.Client)
			if err := c.Reload(&updated); err == nil || !strings.Contains(err.Error(), tc.field) {
				t.Fatalf("Reload error = %v, want %s to require a restart", err, tc.field)
			}
			if got := c.Status().ServerURL; got != cfg.Client.ServerURL {
				t.Fatalf("failed reload changed live config to %q", got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Push
// ---------------------------------------------------------------------------

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
	var syncRequests atomic.Int32
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	fs := newFakeServer()
	fs.syncStatus = func(string) int {
		syncRequests.Add(1)
		<-release
		return 0
	}
	apiServer := httptest.NewServer(fs.handler())
	t.Cleanup(apiServer.Close)
	t.Cleanup(unblock)

	cfg := buildTestCfg(t, apiServer.URL)
	cfg.Client.PushToken = "0123456789abcdef0123456789abcdef"
	c := newTestClient(t, cfg)
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
	for syncRequests.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := syncRequests.Load(); got != 1 {
		t.Fatalf("concurrent push notifications started %d pulls, want 1", got)
	}
	unblock()

	// The pull writes the store into the test's data directory; let it
	// finish before the directory is removed.
	deadline = time.Now().Add(5 * time.Second)
	for c.pushInFlight.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if c.pushInFlight.Load() {
		t.Fatal("push-triggered pull did not finish")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func TestSplitBundle(t *testing.T) {
	full := "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n" +
		"-----BEGIN CERTIFICATE-----\ninter\n-----END CERTIFICATE-----\n"
	cb := splitBundle(storedCert{FullchainPEM: full, KeyPEM: "key"})

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
