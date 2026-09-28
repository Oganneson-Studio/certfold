package ipc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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

// testCertConfig returns a running configuration with the given certificates
// and the CA "le" they can reference.
func testCertConfig(specs ...config.CertificateSpec) *config.ServerConfig {
	return &config.ServerConfig{
		ACME: config.ACMESection{CAs: map[string]config.CAEntry{
			"le": {Directory: "https://acme.example.com/directory"},
		}},
		Certificates: specs,
	}
}

// certDeps returns certificate deps that run cfg and report the named
// certificates as issuing.
func certDeps(cfg *config.ServerConfig, issuing ...string) *CertificateControlDeps {
	return &CertificateControlDeps{
		Current: func() *config.ServerConfig { return cfg },
		Issuing: func(name string) bool { return slices.Contains(issuing, name) },
	}
}

// newTestClient returns a client that reaches ts over TCP through the same
// transport NewClient uses.
func newTestClient(ts *httptest.Server) *Client {
	return newClient(func() (net.Conn, error) { return net.Dial("tcp", ts.Listener.Addr().String()) })
}

func TestClientDialsForEveryRequest(t *testing.T) {
	db := mustOpenDB(t)
	ts := httptest.NewServer(buildIPCRouter(&ipcHandlers{deps: ServerDeps{DB: db}}))
	defer ts.Close()

	var dials atomic.Int32
	c := newClient(func() (net.Conn, error) {
		dials.Add(1)
		return net.Dial("tcp", ts.Listener.Addr().String())
	})
	for i := 1; i <= 3; i++ {
		if _, err := c.ListTokens(context.Background()); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if got := dials.Load(); got != 3 {
		t.Fatalf("dials = %d, want one per request", got)
	}
}

func TestListCerts_Empty(t *testing.T) {
	db := mustOpenDB(t)
	h := &ipcHandlers{deps: ServerDeps{DB: db, Certificates: certDeps(testCertConfig())}}
	ts := httptest.NewServer(buildIPCRouter(h))
	defer ts.Close()

	c := newTestClient(ts)
	certs, err := c.ListCerts(context.Background())
	if err != nil {
		t.Fatalf("ListCerts: %v", err)
	}
	if certs == nil || len(certs) != 0 {
		t.Errorf("expected 0 certs, got %d", len(certs))
	}
}

func TestListCertsReportsConfiguredCertificatesAndState(t *testing.T) {
	db := mustOpenDB(t)
	ctx := context.Background()
	// The store keeps whole seconds.
	now := time.Now().UTC().Truncate(time.Second)
	notAfter := now.Add(60 * 24 * time.Hour)
	issuedAt := now.Add(-30 * 24 * time.Hour)
	certSpec := func(name string) config.CertificateSpec {
		return config.CertificateSpec{Name: name, CA: "le", Domains: []string{name + ".example.com"}, KeyType: "ec256"}
	}
	// Not in name order, which is the order the store lists records in.
	cfg := testCertConfig(certSpec("renewing"), certSpec("api"), certSpec("stale"), certSpec("new"), certSpec("failing"), certSpec("retry"))

	for _, spec := range []config.CertificateSpec{
		certSpec("renewing"),
		certSpec("api"),
		certSpec("failing"),
		// Issued before the domains changed.
		{Name: "stale", CA: "le", Domains: []string{"old.example.com"}, KeyType: "ec256"},
		// No longer configured.
		certSpec("removed"),
	} {
		if err := db.Certs.Upsert(ctx, &store.CertRecord{
			Name:            spec.Name,
			CA:              spec.CA,
			Domains:         spec.Domains,
			SpecFingerprint: config.CertificateSpecFingerprint(cfg, spec),
			FullchainPEM:    "fullchain",
			KeyPEM:          "key",
			NotAfter:        notAfter,
			Fingerprint:     "sha256:" + spec.Name,
			IssuedAt:        issuedAt,
			UpdatedAt:       issuedAt,
		}, nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, status := range []*store.IssuanceStatus{
		{Name: "renewing", Failures: 1, LastError: "order failed", LastAttemptAt: now.Add(-time.Minute), NextAttemptAt: now.Add(4 * time.Minute)},
		{Name: "failing", Failures: 3, LastError: "rate limited", LastAttemptAt: now.Add(-5 * time.Minute), NextAttemptAt: now.Add(15 * time.Minute)},
		// The backoff has expired; the failures and the error remain.
		{Name: "retry", Failures: 2, LastError: "dns timeout", LastAttemptAt: now.Add(-20 * time.Minute), NextAttemptAt: now.Add(-10 * time.Minute)},
		{Name: "removed", Failures: 5, LastError: "removed", LastAttemptAt: now, NextAttemptAt: now.Add(time.Hour)},
	} {
		if err := db.Issuance.Upsert(ctx, status, nil); err != nil {
			t.Fatal(err)
		}
	}

	want := []*CertificateInfo{
		// Issuing wins over a backoff and a stored certificate.
		{Name: "renewing", CA: "le", Domains: []string{"renewing.example.com"},
			NotAfter: notAfter, Fingerprint: "sha256:renewing", IssuedAt: issuedAt, UpdatedAt: issuedAt,
			State: CertStateIssuing, Failures: 1, LastError: "order failed",
			LastAttemptAt: now.Add(-time.Minute), NextAttemptAt: now.Add(4 * time.Minute)},
		{Name: "api", CA: "le", Domains: []string{"api.example.com"},
			NotAfter: notAfter, Fingerprint: "sha256:api", IssuedAt: issuedAt, UpdatedAt: issuedAt,
			State: CertStateValid},
		// Material issued for other domains is not reported.
		{Name: "stale", CA: "le", Domains: []string{"stale.example.com"}, State: CertStatePending},
		{Name: "new", CA: "le", Domains: []string{"new.example.com"}, State: CertStatePending},
		// A backoff wins over a stored certificate.
		{Name: "failing", CA: "le", Domains: []string{"failing.example.com"},
			NotAfter: notAfter, Fingerprint: "sha256:failing", IssuedAt: issuedAt, UpdatedAt: issuedAt,
			State: CertStateBackoff, Failures: 3, LastError: "rate limited",
			LastAttemptAt: now.Add(-5 * time.Minute), NextAttemptAt: now.Add(15 * time.Minute)},
		{Name: "retry", CA: "le", Domains: []string{"retry.example.com"},
			State: CertStatePending, Failures: 2, LastError: "dns timeout",
			LastAttemptAt: now.Add(-20 * time.Minute), NextAttemptAt: now.Add(-10 * time.Minute)},
	}

	h := &ipcHandlers{deps: ServerDeps{DB: db, Certificates: certDeps(cfg, "renewing")}}
	ts := httptest.NewServer(buildIPCRouter(h))
	defer ts.Close()

	got, err := newTestClient(ts).ListCerts(ctx)
	if err != nil {
		t.Fatalf("ListCerts: %v", err)
	}
	if len(got) != len(want) {
		raw, _ := json.Marshal(got)
		t.Fatalf("got %d certificates, want %d: %s", len(got), len(want), raw)
	}
	for i := range want {
		gotJSON, _ := json.Marshal(got[i])
		wantJSON, _ := json.Marshal(want[i])
		if !bytes.Equal(gotJSON, wantJSON) {
			t.Errorf("certificate %d:\n got %s\nwant %s", i, gotJSON, wantJSON)
		}
	}
}

func TestListCertsRejectsUnavailableStatus(t *testing.T) {
	h := &ipcHandlers{deps: ServerDeps{DB: mustOpenDB(t), Certificates: &CertificateControlDeps{}}}
	ts := httptest.NewServer(buildIPCRouter(h))
	defer ts.Close()

	_, err := newTestClient(ts).ListCerts(context.Background())
	if err == nil || !strings.Contains(err.Error(), "501") {
		t.Fatalf("ListCerts error = %v", err)
	}
}

func TestReadEndpointsReturnEmptyArrays(t *testing.T) {
	db := mustOpenDB(t)
	h := &ipcHandlers{deps: ServerDeps{DB: db, Certificates: certDeps(testCertConfig())}}
	ts := httptest.NewServer(buildIPCRouter(h))
	defer ts.Close()

	c := newTestClient(ts)
	ctx := context.Background()
	certs, err := c.ListCerts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	clients, err := c.ListClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := c.ListTokens(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if certs == nil || clients == nil || tokens == nil {
		t.Fatalf("list response contains null array: certs=%v clients=%v tokens=%v", certs, clients, tokens)
	}
}

// TestCertificatesCannotBeWrittenOverIPC guards the removal of the route the
// E2E stack once seeded its certificate through: certificates reach the store
// only by issuance.
func TestCertificatesCannotBeWrittenOverIPC(t *testing.T) {
	db := mustOpenDB(t)
	spec := config.CertificateSpec{Name: "api-prod", CA: "le", Domains: []string{"api.example.com"}, KeyType: "ec256"}
	cfg := testCertConfig(spec)
	router := buildIPCRouter(&ipcHandlers{deps: ServerDeps{DB: db, Certificates: certDeps(cfg)}})

	// The seeding request: a raw store.CertRecord that matches the running
	// configuration.
	body, err := json.Marshal(&store.CertRecord{
		Name:            "api-prod",
		CA:              "le",
		Domains:         []string{"api.example.com"},
		SpecFingerprint: config.CertificateSpecFingerprint(cfg, spec),
		NotAfter:        time.Now().Add(90 * 24 * time.Hour),
		Fingerprint:     "sha256:AA",
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/ipc/v1/certs", bytes.NewReader(body)))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	stored, err := db.Certs.List(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 0 {
		t.Fatalf("the request stored %d certificate records", len(stored))
	}
}

func TestRequestBodyIsLimited(t *testing.T) {
	created := false
	router := buildIPCRouter(&ipcHandlers{deps: ServerDeps{Tokens: &TokenControlDeps{
		Create: func(context.Context, string, time.Duration) (CreateTokenResponse, error) {
			created = true
			return CreateTokenResponse{}, nil
		},
	}}})

	// A well-formed request that is larger than the limit must not be read.
	body, err := json.Marshal(CreateTokenRequest{Name: strings.Repeat("a", maxRequestBody), TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/ipc/v1/tokens", bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if created {
		t.Fatal("the oversized request reached the daemon")
	}
}

func TestRenewCert(t *testing.T) {
	var renewed string
	h := &ipcHandlers{deps: ServerDeps{Certificates: &CertificateControlDeps{
		Renew: func(_ context.Context, name string) error {
			renewed = name
			return nil
		},
	}}}
	ts := httptest.NewServer(buildIPCRouter(h))
	defer ts.Close()

	c := newTestClient(ts)
	if err := c.RenewCert(context.Background(), "api-prod"); err != nil {
		t.Fatalf("RenewCert: %v", err)
	}
	if renewed != "api-prod" {
		t.Fatalf("renewed = %q, want api-prod", renewed)
	}
}

func TestRenewCertRejectsUnavailableAndPropagatesFailure(t *testing.T) {
	t.Run("unavailable", func(t *testing.T) {
		h := &ipcHandlers{deps: ServerDeps{Certificates: &CertificateControlDeps{}}}
		ts := httptest.NewServer(buildIPCRouter(h))
		defer ts.Close()
		err := newTestClient(ts).RenewCert(context.Background(), "api-prod")
		if err == nil || !strings.Contains(err.Error(), "501") {
			t.Fatalf("RenewCert error = %v", err)
		}
	})

	t.Run("issuer failure", func(t *testing.T) {
		h := &ipcHandlers{deps: ServerDeps{Certificates: &CertificateControlDeps{
			Renew: func(context.Context, string) error { return errors.New("acme failed") },
		}}}
		ts := httptest.NewServer(buildIPCRouter(h))
		defer ts.Close()
		err := newTestClient(ts).RenewCert(context.Background(), "api-prod")
		if err == nil || !strings.Contains(err.Error(), "acme failed") {
			t.Fatalf("RenewCert error = %v", err)
		}
	})
}

func TestServerReloadControlEndpoint(t *testing.T) {
	reloaded := false
	h := &ipcHandlers{deps: ServerDeps{Server: &ServerControlDeps{
		Reload: func(context.Context) error {
			reloaded = true
			return nil
		},
	}}}
	ts := httptest.NewServer(buildIPCRouter(h))
	defer ts.Close()

	if err := newTestClient(ts).ReloadServer(context.Background()); err != nil {
		t.Fatalf("ReloadServer: %v", err)
	}
	if !reloaded {
		t.Fatal("server reload callback was not invoked")
	}
}

func TestServerReloadRejectsUnavailableAndPropagatesFailure(t *testing.T) {
	t.Run("unavailable", func(t *testing.T) {
		h := &ipcHandlers{deps: ServerDeps{Server: &ServerControlDeps{}}}
		ts := httptest.NewServer(buildIPCRouter(h))
		defer ts.Close()
		err := newTestClient(ts).ReloadServer(context.Background())
		if err == nil || !strings.Contains(err.Error(), "501") {
			t.Fatalf("ReloadServer error = %v", err)
		}
	})

	t.Run("reload failure", func(t *testing.T) {
		h := &ipcHandlers{deps: ServerDeps{Server: &ServerControlDeps{
			Reload: func(context.Context) error { return errors.New("immutable field changed") },
		}}}
		ts := httptest.NewServer(buildIPCRouter(h))
		defer ts.Close()
		err := newTestClient(ts).ReloadServer(context.Background())
		if err == nil || !strings.Contains(err.Error(), "immutable field changed") {
			t.Fatalf("ReloadServer error = %v", err)
		}
	})
}

func TestListClients(t *testing.T) {
	db := mustOpenDB(t)
	ctx := context.Background()
	_ = db.Clients.Upsert(ctx, &store.ClientRecord{
		Name:        "web-1",
		Fingerprint: "sha256:AA",
		EnrolledAt:  time.Now(),
	}, nil)

	h := &ipcHandlers{deps: ServerDeps{DB: db}}
	ts := httptest.NewServer(buildIPCRouter(h))
	defer ts.Close()

	c := newTestClient(ts)
	clients, err := c.ListClients(ctx)
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(clients) != 1 || clients[0].Name != "web-1" {
		t.Errorf("expected [web-1], got %v", clients)
	}
}

func TestCreateToken(t *testing.T) {
	var gotName string
	var gotTTL time.Duration
	want := CreateTokenResponse{
		Token:               "opaque-token",
		ServerURL:           "https://sigil.example.com",
		PublicURLConfigured: true,
	}
	h := &ipcHandlers{deps: ServerDeps{Tokens: &TokenControlDeps{
		Create: func(_ context.Context, name string, ttl time.Duration) (CreateTokenResponse, error) {
			gotName, gotTTL = name, ttl
			return want, nil
		},
	}}}
	ts := httptest.NewServer(buildIPCRouter(h))
	defer ts.Close()

	created, err := newTestClient(ts).CreateToken(context.Background(), CreateTokenRequest{
		Name: "web-1",
		TTL:  10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if gotName != "web-1" || gotTTL != 10*time.Minute {
		t.Fatalf("daemon received name %q and ttl %s", gotName, gotTTL)
	}
	if *created != want {
		t.Fatalf("response = %+v, want %+v", *created, want)
	}
}

func TestCreateTokenReportsDaemonRejection(t *testing.T) {
	h := &ipcHandlers{deps: ServerDeps{Tokens: &TokenControlDeps{
		Create: func(context.Context, string, time.Duration) (CreateTokenResponse, error) {
			return CreateTokenResponse{}, errors.New(`invalid client name "Web 1"`)
		},
	}}}
	ts := httptest.NewServer(buildIPCRouter(h))
	defer ts.Close()

	_, err := newTestClient(ts).CreateToken(context.Background(), CreateTokenRequest{Name: "Web 1", TTL: time.Hour})
	if err == nil || !strings.Contains(err.Error(), `invalid client name "Web 1"`) || !strings.Contains(err.Error(), "422") {
		t.Fatalf("CreateToken error = %v, want the daemon's reason with status 422", err)
	}
}

func TestDeleteToken(t *testing.T) {
	db := mustOpenDB(t)
	ctx := context.Background()
	_ = db.Tokens.Upsert(ctx, &store.TokenRecord{
		TokenID:   "tok-1",
		Name:      "web-1",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}, nil)

	h := &ipcHandlers{deps: ServerDeps{DB: db}}
	ts := httptest.NewServer(buildIPCRouter(h))
	defer ts.Close()

	c := newTestClient(ts)
	if err := c.DeleteToken(ctx, "tok-1"); err != nil {
		t.Fatalf("DeleteToken: %v", err)
	}
	tokens, _ := c.ListTokens(ctx)
	if len(tokens) != 0 {
		t.Errorf("expected 0 tokens after delete, got %d", len(tokens))
	}
}

func TestReadEndpointsDoNotExposeStoredSecrets(t *testing.T) {
	db := mustOpenDB(t)
	ctx := context.Background()
	spec := config.CertificateSpec{Name: "api-prod", CA: "le", Domains: []string{"api.example.com"}, KeyType: "ec256"}
	cfg := testCertConfig(spec)
	// The record matches the running configuration, so it is listed.
	if err := db.Certs.Upsert(ctx, &store.CertRecord{
		Name:            "api-prod",
		CA:              "le",
		Domains:         []string{"api.example.com"},
		SpecFingerprint: config.CertificateSpecFingerprint(cfg, spec),
		FullchainPEM:    "sentinel-fullchain-pem",
		KeyPEM:          "sentinel-private-key-pem",
		Fingerprint:     "sha256:cc",
		UpdatedAt:       time.Now(),
	}, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Clients.Upsert(ctx, &store.ClientRecord{
		Name:               "web-1",
		Fingerprint:        "sha256:AA",
		EnrolledAt:         time.Now(),
		PendingFingerprint: "sentinel-pending-fingerprint",
	}, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Tokens.Upsert(ctx, &store.TokenRecord{
		TokenID:    "tok-1",
		Name:       "web-1",
		SecretHash: "sentinel-secret-hash",
		ExpiresAt:  time.Now().Add(time.Hour),
		CreatedAt:  time.Now(),
	}, nil); err != nil {
		t.Fatal(err)
	}

	h := &ipcHandlers{deps: ServerDeps{DB: db, Certificates: certDeps(cfg)}}
	ts := httptest.NewServer(buildIPCRouter(h))
	defer ts.Close()

	tests := []struct {
		name            string
		path            string
		forbiddenFields []string
		forbiddenValues []string
		// listedValues show that the record holding the secrets was read.
		listedValues []string
	}{
		{
			name:            "certificates",
			path:            "/ipc/v1/certs",
			forbiddenFields: []string{"keypem", "fullchainpem"},
			forbiddenValues: []string{"sentinel-private-key-pem", "sentinel-fullchain-pem"},
			listedValues:    []string{"sha256:cc"},
		},
		{
			name:            "clients",
			path:            "/ipc/v1/clients",
			forbiddenFields: []string{"pendingfingerprint"},
			forbiddenValues: []string{"sentinel-pending-fingerprint"},
		},
		{
			name:            "tokens",
			path:            "/ipc/v1/tokens",
			forbiddenFields: []string{"secrethash"},
			forbiddenValues: []string{"sentinel-secret-hash"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := ts.Client().Get(ts.URL + tt.path)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
			}

			lowerBody := strings.ToLower(string(body))
			compactBody := strings.ReplaceAll(lowerBody, "_", "")
			for _, field := range tt.forbiddenFields {
				if strings.Contains(compactBody, field) {
					t.Fatalf("response exposed forbidden field %q: %s", field, body)
				}
			}
			for _, value := range tt.forbiddenValues {
				if strings.Contains(lowerBody, value) {
					t.Fatalf("response exposed forbidden value %q: %s", value, body)
				}
			}
			for _, value := range tt.listedValues {
				if !strings.Contains(lowerBody, value) {
					t.Fatalf("response lacks %q of the stored record: %s", value, body)
				}
			}
		})
	}
}

func TestClientControlEndpoints(t *testing.T) {
	var fetched string
	reloaded := false
	h := &ipcHandlers{deps: ServerDeps{Client: &ClientControlDeps{
		State: func(context.Context) (ClientState, error) {
			return ClientState{
				Name:      "web-1",
				ServerURL: "https://sigil.example.com",
				Online:    true,
				Certs:     []ClientCertState{{Name: "api-prod", Fingerprint: "sha256:AA"}},
			}, nil
		},
		Fetch: func(_ context.Context, name string) error {
			fetched = name
			return nil
		},
		Reload: func(context.Context) error {
			reloaded = true
			return nil
		},
	}}}
	ts := httptest.NewServer(buildIPCRouter(h))
	defer ts.Close()

	c := newTestClient(ts)
	state, err := c.GetClientState(context.Background())
	if err != nil {
		t.Fatalf("GetClientState: %v", err)
	}
	if state.Name != "web-1" || !state.Online || len(state.Certs) != 1 {
		t.Fatalf("unexpected client state: %+v", state)
	}
	if err := c.FetchClient(context.Background(), "api-prod"); err != nil {
		t.Fatalf("FetchClient: %v", err)
	}
	if fetched != "api-prod" {
		t.Fatalf("fetch name = %q, want api-prod", fetched)
	}
	if err := c.ReloadClient(context.Background()); err != nil {
		t.Fatalf("ReloadClient: %v", err)
	}
	if !reloaded {
		t.Fatal("reload callback was not invoked")
	}
}

func TestClientOnlyRouterDoesNotExposeServerState(t *testing.T) {
	h := &ipcHandlers{deps: ServerDeps{Client: &ClientControlDeps{}}}
	ts := httptest.NewServer(buildIPCRouter(h))
	defer ts.Close()

	resp, err := ts.Client().Get(ts.URL + "/ipc/v1/tokens")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

// TestServe exercises the full Serve path on a real listener.
func TestServe(t *testing.T) {
	db := mustOpenDB(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, l, ServerDeps{DB: db, Certificates: certDeps(testCertConfig())}) }()

	c := newClient(func() (net.Conn, error) { return net.Dial("tcp", l.Addr().String()) })
	certs, err := c.ListCerts(ctx)
	if err != nil {
		t.Fatalf("ListCerts: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("expected empty, got %v", certs)
	}

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve returned %v after cancellation, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after cancellation")
	}
}
