package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

func writeManagementTestConfig(t *testing.T, certificates string) string {
	t.Helper()
	t.Setenv("SIGIL_TEST_ACCESS_KEY", "expanded-access-key")
	t.Setenv("SIGIL_TEST_SECRET_KEY", "expanded-secret-key")
	path := filepath.Join(t.TempDir(), "server.yaml")
	raw := `# preserve this operator comment
server:
  listen: ":8443"
  data_dir: "C:/sigil-test"
acme:
  email: "admin@example.com"
  default_ca: "le"
  cas:
    le:
      directory: "https://acme.example.com/directory"
dns_providers:
  route:
    type: route53
    access_key: ${SIGIL_TEST_ACCESS_KEY}
    secret_key: ${SIGIL_TEST_SECRET_KEY}
certificates:
` + certificates
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type fakeServerReloader struct {
	calls int
	err   error
}

func (r *fakeServerReloader) ReloadServer(context.Context) error {
	r.calls++
	return r.err
}

func stubServerReloader(t *testing.T, client serverReloader, dialErr error) {
	t.Helper()
	previous := dialServerReloader
	dialServerReloader = func(string) (serverReloader, error) { return client, dialErr }
	t.Cleanup(func() { dialServerReloader = previous })
}

func TestManagementJSONViewsDoNotExposePrivateMaterial(t *testing.T) {
	certJSON, err := json.Marshal(newCertificateDetails(&ipc.CertificateInfo{
		Name: "api-prod",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(certJSON)), "key_pem") || strings.Contains(strings.ToLower(string(certJSON)), "fullchain_pem") {
		t.Fatalf("certificate JSON leaked private material: %s", certJSON)
	}
}

func TestServerIPCSocketResolution(t *testing.T) {
	configured := filepath.Join(t.TempDir(), "configured.sock")
	path := writeManagementTestConfig(t, "  []\n")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte("  data_dir:"), []byte("  ipc_socket: \""+strings.ReplaceAll(configured, "\\", "\\\\")+"\"\n  data_dir:"), 1)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := NewRootCmd()
	if err := cmd.PersistentFlags().Set("config", path); err != nil {
		t.Fatal(err)
	}
	if got := serverIPCSocket(cmd); got != configured {
		t.Fatalf("socket = %q, want configured %q", got, configured)
	}

	// Locating the daemon must not require the DNS credentials it expands.
	unset := bytes.ReplaceAll(raw, []byte("${SIGIL_TEST_"), []byte("${SIGIL_TEST_UNSET_"))
	if err := os.WriteFile(path, unset, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := serverIPCSocket(cmd); got != configured {
		t.Fatalf("socket with unset credential variables = %q, want configured %q", got, configured)
	}

	explicit := filepath.Join(t.TempDir(), "explicit.sock")
	if err := cmd.PersistentFlags().Set("ipc", explicit); err != nil {
		t.Fatal(err)
	}
	if got := serverIPCSocket(cmd); got != explicit {
		t.Fatalf("socket = %q, want explicit %q", got, explicit)
	}

	missing := NewRootCmd()
	if err := missing.PersistentFlags().Set("config", filepath.Join(t.TempDir(), "missing.yaml")); err != nil {
		t.Fatal(err)
	}
	if got := serverIPCSocket(missing); got != ipc.DefaultServerSocket() {
		t.Fatalf("socket = %q, want default %q", got, ipc.DefaultServerSocket())
	}
}

func TestReloadDoesNotFallBackToDefaultSocket(t *testing.T) {
	configured := filepath.Join(t.TempDir(), "configured.sock")
	path := writeManagementTestConfig(t, "  []\n")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte("  data_dir:"), []byte("  ipc_socket: \""+strings.ReplaceAll(configured, "\\", "\\\\")+"\"\n  data_dir:"), 1)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	var dialed []string
	previous := dialServerReloader
	dialServerReloader = func(socket string) (serverReloader, error) {
		dialed = append(dialed, socket)
		if socket == configured {
			return nil, errors.New("connection refused")
		}
		// Some daemon still answers on the platform default socket.
		return &fakeServerReloader{}, nil
	}
	t.Cleanup(func() { dialServerReloader = previous })

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"--config", path, "reload"})
	err = cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--ipc") {
		t.Fatalf("reload error = %v, want a failure that points to --ipc", err)
	}
	if len(dialed) != 1 || dialed[0] != configured {
		t.Fatalf("dialed %q, want only the configured socket %q", dialed, configured)
	}
}

func TestCertAddReloadsRunningServer(t *testing.T) {
	path := writeManagementTestConfig(t, "  []\n")
	reloader := &fakeServerReloader{}
	stubServerReloader(t, reloader, nil)
	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"--config", path, "cert", "add", "api-prod",
		"--domains", "api.example.com", "--dns", "route",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if reloader.calls != 1 {
		t.Fatalf("reload calls = %d, want 1", reloader.calls)
	}
	cfg, err := config.LoadServer(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Certificates) != 1 || cfg.Certificates[0].Name != "api-prod" {
		t.Fatalf("certificates = %+v", cfg.Certificates)
	}
}

func TestCertRemoveReloadsRunningServer(t *testing.T) {
	path := writeManagementTestConfig(t, `  - name: api-prod
    domains: [api.example.com]
    ca: le
    dns_provider: route
    key_type: ec256
`)
	reloader := &fakeServerReloader{}
	stubServerReloader(t, reloader, nil)
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"--config", path, "cert", "remove", "api-prod"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if reloader.calls != 1 {
		t.Fatalf("reload calls = %d, want 1", reloader.calls)
	}
	cfg, err := config.LoadServer(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Certificates) != 0 {
		t.Fatalf("certificates = %+v", cfg.Certificates)
	}
}

func TestCertAddSucceedsWhenDaemonIsNotRunning(t *testing.T) {
	path := writeManagementTestConfig(t, "  []\n")
	// Dial for real: a stopped daemon leaves no endpoint behind.
	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"--config", path, "--ipc", testIPCSocket(t), "cert", "add", "api-prod",
		"--domains", "api.example.com", "--dns", "route",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cert add should persist for next startup: %v", err)
	}
	cfg, err := config.LoadServer(path)
	if err != nil || len(cfg.Certificates) != 1 {
		t.Fatalf("persisted config = %+v, err = %v", cfg, err)
	}
}

func TestCertAddTellsStoppedDaemonFromUnreachableOne(t *testing.T) {
	tests := []struct {
		name       string
		dialErr    error
		notRunning bool
	}{
		{name: "connection refused", dialErr: fmt.Errorf("ipc dial: %w", syscall.ECONNREFUSED), notRunning: true},
		{name: "permission denied", dialErr: fmt.Errorf("ipc dial: %w", fs.ErrPermission)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeManagementTestConfig(t, "  []\n")
			stubServerReloader(t, nil, tt.dialErr)
			cmd := NewRootCmd()
			cmd.SetArgs([]string{
				"--config", path, "cert", "add", "api-prod",
				"--domains", "api.example.com", "--dns", "route",
			})
			err := cmd.Execute()
			if tt.notRunning {
				if err != nil {
					t.Fatalf("cert add with a stopped daemon: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "configuration saved") || !strings.Contains(err.Error(), "could not be notified") {
				t.Fatalf("cert add error = %v, want a saved but not notified failure", err)
			}
			cfg, loadErr := config.LoadServer(path)
			if loadErr != nil || len(cfg.Certificates) != 1 {
				t.Fatalf("persisted config = %+v, err = %v", cfg, loadErr)
			}
		})
	}
}

// serveCertificates serves the certificates of cfg, backed by db, on a new
// IPC endpoint and returns the endpoint. Each stored certificate is due for
// renewal by ARI 20 days before it expires.
func serveCertificates(t *testing.T, db *store.DB, cfg *config.ServerConfig) string {
	t.Helper()
	socket := testIPCSocket(t)
	l, err := ipc.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := ipc.NewServer(ipc.ServerDeps{DB: db, Certificates: &ipc.CertificateControlDeps{
		Current: func() *config.ServerConfig { return cfg },
		Issuing: func(string) bool { return false },
		RenewalPlan: func(record *store.CertRecord) (time.Time, string) {
			return record.NotAfter.Add(-20 * 24 * time.Hour), "ari"
		},
	}})
	context.AfterFunc(ctx, func() { _ = srv.Close() })
	go func() { _ = srv.Serve(l) }()
	if _, err := ipc.NewClient(socket); err != nil {
		skipWithoutPipeAccess(t, err)
		t.Fatal(err)
	}
	return socket
}

// runSigils runs sigils with args and returns what it printed to stdout.
func runSigils(t *testing.T, args ...string) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	printed := make(chan []byte)
	go func() {
		raw, _ := io.ReadAll(r)
		printed <- raw
	}()
	root := NewRootCmd()
	root.SetArgs(args)
	runErr := root.Execute()
	os.Stdout = stdout
	_ = w.Close()
	out := <-printed
	_ = r.Close()
	if runErr != nil {
		t.Fatalf("sigils %s: %v", strings.Join(args, " "), runErr)
	}
	return string(out)
}

func TestCertListAndShowReportIssuanceState(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	// The store keeps whole seconds.
	now := time.Now().UTC().Truncate(time.Second)
	notAfter := now.Add(60 * 24 * time.Hour)
	renewAt := notAfter.Add(-20 * 24 * time.Hour) // as serveCertificates plans it
	nextAttempt := now.Add(20 * time.Minute)
	mail := config.CertificateSpec{Name: "mail", CA: "le", Domains: []string{"mail.example.com"}, KeyType: "ec256"}
	api := config.CertificateSpec{Name: "api-prod", CA: "le", Domains: []string{"api.example.com"}, KeyType: "ec256",
		Subscribers: []string{"web-1", "web-2"}}
	cfg := &config.ServerConfig{
		ACME: config.ACMESection{CAs: map[string]config.CAEntry{
			"le": {Directory: "https://acme.example.com/directory"},
		}},
		Certificates: []config.CertificateSpec{mail, api},
	}
	// api-prod holds material for the running configuration; mail has never
	// been issued and waits out a backoff.
	if err := db.Certs.Upsert(ctx, &store.CertRecord{
		Name:            "api-prod",
		CA:              "le",
		Domains:         api.Domains,
		SpecFingerprint: config.CertificateSpecFingerprint(cfg, api),
		NotAfter:        notAfter,
		Fingerprint:     "sha256:AA",
		IssuedAt:        now,
		UpdatedAt:       now,
	}, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Issuance.Upsert(ctx, &store.IssuanceStatus{
		Name:          "mail",
		Failures:      2,
		LastError:     "acme: rate limited",
		LastAttemptAt: now,
		NextAttemptAt: nextAttempt,
	}, nil); err != nil {
		t.Fatal(err)
	}
	socket := serveCertificates(t, db, cfg)

	table := runSigils(t, "--ipc", socket, "cert", "list")
	wantRows := [][]string{
		{"NAME", "CA", "DOMAINS", "STATE", "NOT", "AFTER", "RENEW", "AT"},
		{"mail", "le", "mail.example.com", "backoff", "-", "-"},
		{"api-prod", "le", "api.example.com", "valid", notAfter.Format("2006-01-02"), renewAt.Format("2006-01-02"), "(ari)"},
	}
	lines := strings.Split(strings.TrimSuffix(table, "\n"), "\n")
	if len(lines) != len(wantRows) {
		t.Fatalf("cert list printed %d lines, want %d:\n%s", len(lines), len(wantRows), table)
	}
	for i, want := range wantRows {
		if got := strings.Fields(lines[i]); !slices.Equal(got, want) {
			t.Errorf("cert list line %d = %q, want %q", i, got, want)
		}
	}

	sameJSON := func(got, want string) {
		t.Helper()
		var gotValue, wantValue any
		if err := json.Unmarshal([]byte(got), &gotValue); err != nil {
			t.Fatalf("output is not JSON: %v\n%s", err, got)
		}
		if err := json.Unmarshal([]byte(want), &wantValue); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(gotValue, wantValue) {
			t.Errorf("JSON output:\n got %s\nwant %s", got, want)
		}
	}
	mailJSON := fmt.Sprintf(`{"name":"mail","ca":"le","domains":["mail.example.com"],"subscribers":[],"state":"backoff","failures":2,`+
		`"last_error":"acme: rate limited","last_attempt_at":%q,"next_attempt_at":%q}`,
		now.Format(time.RFC3339), nextAttempt.Format(time.RFC3339))
	apiJSON := fmt.Sprintf(`{"name":"api-prod","ca":"le","domains":["api.example.com"],"subscribers":["web-1","web-2"],"not_after":%q,`+
		`"renew_at":%q,"renew_source":"ari","fingerprint":"sha256:AA",`+
		`"issued_at":%q,"updated_at":%q,"state":"valid","failures":0}`,
		notAfter.Format(time.RFC3339), renewAt.Format(time.RFC3339), now.Format(time.RFC3339), now.Format(time.RFC3339))
	sameJSON(runSigils(t, "--ipc", socket, "--json", "cert", "list"), "["+mailJSON+","+apiJSON+"]")
	sameJSON(runSigils(t, "--ipc", socket, "--json", "cert", "show", "mail"), mailJSON)
	sameJSON(runSigils(t, "--ipc", socket, "--json", "cert", "show", "api-prod"), apiJSON)

	wantShow := map[string]string{
		"mail": "Name:         mail\n" +
			"CA:           le\n" +
			"Domains:      mail.example.com\n" +
			"Subscribers:  -\n" +
			"Not After:    -\n" +
			"Renew At:     -\n" +
			"State:        backoff\n" +
			"Failures:     2\n" +
			"Last Error:   acme: rate limited\n" +
			"Next Attempt: " + nextAttempt.Format("2006-01-02 15:04:05 MST") + "\n",
		"api-prod": "Name:         api-prod\n" +
			"CA:           le\n" +
			"Domains:      api.example.com\n" +
			"Subscribers:  web-1, web-2\n" +
			"Not After:    " + notAfter.Format("2006-01-02") + "\n" +
			"Renew At:     " + renewAt.Format("2006-01-02 15:04:05 MST") + " (ari)\n" +
			"State:        valid\n" +
			"Failures:     0\n" +
			"Last Error:   -\n" +
			"Next Attempt: -\n",
	}
	for name, want := range wantShow {
		if got := runSigils(t, "--ipc", socket, "cert", "show", name); got != want {
			t.Errorf("cert show %s printed:\n%s\nwant:\n%s", name, got, want)
		}
	}
}

func TestCertAddReportsRejectedLiveReloadAfterSaving(t *testing.T) {
	path := writeManagementTestConfig(t, "  []\n")
	reloader := &fakeServerReloader{err: errors.New("reload rejected")}
	stubServerReloader(t, reloader, nil)
	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"--config", path, "cert", "add", "api-prod",
		"--domains", "api.example.com", "--dns", "route",
	})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "configuration saved") || !strings.Contains(err.Error(), "reload rejected") {
		t.Fatalf("error = %v", err)
	}
	cfg, loadErr := config.LoadServer(path)
	if loadErr != nil || len(cfg.Certificates) != 1 {
		t.Fatalf("persisted config = %+v, err = %v", cfg, loadErr)
	}
}
