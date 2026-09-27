package ipc

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

// startTestServer starts an IPC server listening on a random TCP address.
// Returns the base URL of the test server.
func startTestServer(t *testing.T, db *store.DB) *http.Server {
	t.Helper()
	srv := NewServer(ServerDeps{DB: db})
	return srv
}

// newTestClient creates a client backed by httptest.Server transport (TCP).
func newTestClient(ts *httptest.Server) *Client {
	return &Client{
		http: ts.Client(),
		base: ts.URL,
	}
}

func TestListCerts_Empty(t *testing.T) {
	db := mustOpenDB(t)
	h := &ipcHandlers{deps: ServerDeps{DB: db}}
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

func TestReadEndpointsReturnEmptyArrays(t *testing.T) {
	db := mustOpenDB(t)
	h := &ipcHandlers{deps: ServerDeps{DB: db}}
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
	state, err := c.GetState(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if certs == nil || clients == nil || tokens == nil {
		t.Fatalf("list response contains null array: certs=%v clients=%v tokens=%v", certs, clients, tokens)
	}
	if state.Certs == nil || state.Clients == nil || state.Tokens == nil {
		t.Fatalf("state response contains null array: %+v", state)
	}
}

func TestUpsertAndListCerts(t *testing.T) {
	db := mustOpenDB(t)
	h := &ipcHandlers{deps: ServerDeps{DB: db}}
	ts := httptest.NewServer(buildIPCRouter(h))
	defer ts.Close()

	c := newTestClient(ts)
	rec := &store.CertRecord{
		Name:      "api-prod",
		CA:        "le",
		Domains:   []string{"api.example.com"},
		NotAfter:  time.Now().Add(90 * 24 * time.Hour),
		UpdatedAt: time.Now(),
	}
	if err := c.UpsertCert(context.Background(), rec); err != nil {
		t.Fatalf("UpsertCert: %v", err)
	}
	certs, err := c.ListCerts(context.Background())
	if err != nil {
		t.Fatalf("ListCerts: %v", err)
	}
	if len(certs) != 1 || certs[0].Name != "api-prod" {
		t.Errorf("expected [api-prod], got %v", certs)
	}
}

func TestDeleteCert(t *testing.T) {
	db := mustOpenDB(t)
	ctx := context.Background()
	_ = db.Certs.Upsert(ctx, &store.CertRecord{
		Name: "api-prod", CA: "le", Domains: []string{"x.com"}, UpdatedAt: time.Now(),
	}, nil)

	h := &ipcHandlers{deps: ServerDeps{DB: db}}
	ts := httptest.NewServer(buildIPCRouter(h))
	defer ts.Close()

	c := newTestClient(ts)
	if err := c.DeleteCert(ctx, "api-prod"); err != nil {
		t.Fatalf("DeleteCert: %v", err)
	}
	certs, _ := c.ListCerts(ctx)
	if len(certs) != 0 {
		t.Errorf("expected 0 certs after delete, got %d", len(certs))
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

func TestCreateAndListTokens(t *testing.T) {
	db := mustOpenDB(t)
	h := &ipcHandlers{deps: ServerDeps{DB: db}}
	ts := httptest.NewServer(buildIPCRouter(h))
	defer ts.Close()

	c := newTestClient(ts)
	tok, err := c.CreateToken(context.Background(), createTokenRequest{
		Name: "web-1",
		TTL:  time.Hour,
	})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if tok == "" {
		t.Fatal("empty token")
	}

	tokens, err := c.ListTokens(context.Background())
	if err != nil {
		t.Fatalf("ListTokens: %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(tokens))
	}
	if tokens[0].Name != "web-1" {
		t.Errorf("token name: %q", tokens[0].Name)
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

func TestGetState(t *testing.T) {
	db := mustOpenDB(t)
	ctx := context.Background()
	_ = db.Certs.Upsert(ctx, &store.CertRecord{
		Name: "api-prod", CA: "le", Domains: []string{"x.com"}, UpdatedAt: time.Now(),
	}, nil)
	_ = db.Clients.Upsert(ctx, &store.ClientRecord{
		Name:        "web-1",
		Fingerprint: "sha256:BB",
		EnrolledAt:  time.Now(),
	}, nil)

	h := &ipcHandlers{deps: ServerDeps{DB: db}}
	ts := httptest.NewServer(buildIPCRouter(h))
	defer ts.Close()

	c := newTestClient(ts)
	st, err := c.GetState(ctx)
	if err != nil {
		t.Fatalf("GetState: %v", err)
	}
	if len(st.Certs) != 1 {
		t.Errorf("expected 1 cert in state, got %d", len(st.Certs))
	}
	if len(st.Clients) != 1 {
		t.Errorf("expected 1 client in state, got %d", len(st.Clients))
	}
}

func TestReadEndpointsDoNotExposeStoredSecrets(t *testing.T) {
	db := mustOpenDB(t)
	ctx := context.Background()
	if err := db.Certs.Upsert(ctx, &store.CertRecord{
		Name:         "api-prod",
		CA:           "le",
		Domains:      []string{"api.example.com"},
		FullchainPEM: "sentinel-fullchain-pem",
		KeyPEM:       "sentinel-private-key-pem",
		UpdatedAt:    time.Now(),
	}, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Clients.Upsert(ctx, &store.ClientRecord{
		Name:               "web-1",
		Fingerprint:        "sha256:AA",
		EnrolledAt:         time.Now(),
		PushEndpoint:       "https://push.example.com/notify",
		PushToken:          "sentinel-push-token",
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

	h := &ipcHandlers{deps: ServerDeps{DB: db}}
	ts := httptest.NewServer(buildIPCRouter(h))
	defer ts.Close()

	tests := []struct {
		name            string
		path            string
		forbiddenFields []string
		forbiddenValues []string
	}{
		{
			name:            "certificates",
			path:            "/ipc/v1/certs",
			forbiddenFields: []string{"keypem", "fullchainpem"},
			forbiddenValues: []string{"sentinel-private-key-pem", "sentinel-fullchain-pem"},
		},
		{
			name:            "clients",
			path:            "/ipc/v1/clients",
			forbiddenFields: []string{"pushtoken", "pendingfingerprint"},
			forbiddenValues: []string{"sentinel-push-token", "sentinel-pending-fingerprint"},
		},
		{
			name:            "tokens",
			path:            "/ipc/v1/tokens",
			forbiddenFields: []string{"secrethash"},
			forbiddenValues: []string{"sentinel-secret-hash"},
		},
		{
			name:            "state",
			path:            "/ipc/v1/state",
			forbiddenFields: []string{"keypem", "fullchainpem", "pushtoken", "pendingfingerprint", "secrethash"},
			forbiddenValues: []string{"sentinel-private-key-pem", "sentinel-fullchain-pem", "sentinel-push-token", "sentinel-pending-fingerprint", "sentinel-secret-hash"},
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
				Certs:     map[string]string{"api-prod": "sha256:AA"},
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

	resp, err := ts.Client().Get(ts.URL + "/ipc/v1/state")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

// TestServe_NetPipe exercises the full Serve path using net.Pipe.
func TestServe_NetPipe(t *testing.T) {
	db := mustOpenDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Wrap net.Pipe in a listener.
	serverConn, clientConn := net.Pipe()
	l := &singleConnListener{conn: serverConn}

	go func() {
		_ = Serve(ctx, l, ServerDeps{DB: db})
	}()

	// Use clientConn to make a raw HTTP request.
	c := newClientFromConn(clientConn)
	certs, err := c.ListCerts(ctx)
	if err != nil {
		t.Fatalf("ListCerts over pipe: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("expected empty, got %v", certs)
	}
}

// singleConnListener is a net.Listener that returns a single conn then blocks.
type singleConnListener struct {
	conn    net.Conn
	served  bool
	closeCh chan struct{}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if !l.served {
		l.served = true
		l.closeCh = make(chan struct{})
		return l.conn, nil
	}
	<-l.closeCh
	return nil, net.ErrClosed
}
func (l *singleConnListener) Close() error {
	if l.closeCh != nil {
		close(l.closeCh)
	}
	return nil
}
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

// TestRandomHexID ensures uniqueness.
func TestRandomHexID(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 50; i++ {
		id := randomHexID()
		if len(id) != 16 {
			t.Errorf("id length: got %d, want 16", len(id))
		}
		if ids[id] {
			t.Errorf("duplicate id: %q", id)
		}
		ids[id] = true
	}
}
