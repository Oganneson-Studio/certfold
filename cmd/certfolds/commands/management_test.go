package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Oganneson-Studio/certfold/internal/config"
	"github.com/Oganneson-Studio/certfold/internal/ipc"
	"github.com/Oganneson-Studio/certfold/internal/store"
)

// absPath makes path, a Unix absolute path, absolute on the OS running the
// test: on Windows it puts it on drive C:. Windows takes the slashes of
// C:/certfold-test for separators, and YAML reads slashes as they are in any
// quoting, unlike backslashes.
func absPath(path string) string {
	if runtime.GOOS == "windows" {
		return "C:" + path
	}
	return path
}

func writeManagementTestConfig(t *testing.T, certificates string) string {
	t.Helper()
	t.Setenv("CERTFOLD_TEST_ACCESS_KEY", "expanded-access-key")
	t.Setenv("CERTFOLD_TEST_SECRET_KEY", "expanded-secret-key")
	path := filepath.Join(t.TempDir(), "server.yaml")
	raw := `# preserve this operator comment
server:
  listen: ":8443"
  data_dir: "` + absPath("/certfold-test") + `"
acme:
  email: "admin@example.com"
  default_ca: "le"
  cas:
    le:
      directory: "https://acme.example.com/directory"
dns_providers:
  route:
    type: route53
    access_key: ${CERTFOLD_TEST_ACCESS_KEY}
    secret_key: ${CERTFOLD_TEST_SECRET_KEY}
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
	if got, err := serverIPCSocket(cmd); err != nil || got != configured {
		t.Fatalf("socket = %q, %v; want configured %q", got, err, configured)
	}

	// Locating the daemon must not require the DNS credentials it expands.
	unset := bytes.ReplaceAll(raw, []byte("${CERTFOLD_TEST_"), []byte("${CERTFOLD_TEST_UNSET_"))
	if err := os.WriteFile(path, unset, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := serverIPCSocket(cmd); err != nil || got != configured {
		t.Fatalf("socket with unset credential variables = %q, %v; want configured %q", got, err, configured)
	}

	explicit := filepath.Join(t.TempDir(), "explicit.sock")
	if err := cmd.PersistentFlags().Set("ipc", explicit); err != nil {
		t.Fatal(err)
	}
	if got, err := serverIPCSocket(cmd); err != nil || got != explicit {
		t.Fatalf("socket = %q, %v; want explicit %q", got, err, explicit)
	}

	missing := NewRootCmd()
	if err := missing.PersistentFlags().Set("config", filepath.Join(t.TempDir(), "missing.yaml")); err != nil {
		t.Fatal(err)
	}
	if got, err := serverIPCSocket(missing); err != nil || got != ipc.DefaultServerSocket() {
		t.Fatalf("socket = %q, %v; want default %q", got, err, ipc.DefaultServerSocket())
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

// An ipc_socket that cannot be read is an error that names the file, the
// field and --ipc: the default socket may belong to another daemon, which
// would reload its own configuration.
func TestReloadRefusesUnreadableIPCSocket(t *testing.T) {
	for _, socket := range []string{"configured.sock", "${CERTFOLD_TEST_UNSET_SOCKET}"} {
		path := writeManagementTestConfig(t, "  []\n")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		raw = bytes.Replace(raw, []byte("  data_dir:"), []byte("  ipc_socket: \""+socket+"\"\n  data_dir:"), 1)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}

		var dialed []string
		previous := dialServerReloader
		dialServerReloader = func(socket string) (serverReloader, error) {
			dialed = append(dialed, socket)
			return &fakeServerReloader{}, nil
		}
		t.Cleanup(func() { dialServerReloader = previous })

		cmd := NewRootCmd()
		cmd.SetArgs([]string{"--config", path, "reload"})
		err = cmd.Execute()
		if len(dialed) != 0 {
			t.Fatalf("ipc_socket %s: dialed %q, want no socket", socket, dialed)
		}
		for _, want := range []string{path, "server.ipc_socket", "--ipc"} {
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("ipc_socket %s: reload error = %v, want one that names %s", socket, err, want)
			}
		}
	}
}

// A daemon runs on the socket of server.yaml, where data_dir has since been
// made relative: reload must reach that daemon, which says what is wrong
// with the file, and not a daemon on the default socket.
func TestReloadWithInvalidDataDirReachesConfiguredSocket(t *testing.T) {
	configured := filepath.Join(t.TempDir(), "configured.sock")
	path := writeManagementTestConfig(t, "  []\n")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte("  data_dir: \""+absPath("/certfold-test")+"\""),
		[]byte("  ipc_socket: \""+strings.ReplaceAll(configured, "\\", "\\\\")+"\"\n  data_dir: \"certfold-data\""), 1)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	var dialed []string
	previous := dialServerReloader
	dialServerReloader = func(socket string) (serverReloader, error) {
		dialed = append(dialed, socket)
		if socket == configured {
			return &fakeServerReloader{err: errors.New(`server.data_dir: must be an absolute path, got "certfold-data"`)}, nil
		}
		return &fakeServerReloader{}, nil
	}
	t.Cleanup(func() { dialServerReloader = previous })

	cmd := NewRootCmd()
	cmd.SetArgs([]string{"--config", path, "reload"})
	err = cmd.Execute()
	if len(dialed) != 1 || dialed[0] != configured {
		t.Fatalf("dialed %q, want only the configured socket %q", dialed, configured)
	}
	if err == nil || !strings.Contains(err.Error(), "server.data_dir") {
		t.Fatalf("reload error = %v, want the daemon's error about server.data_dir", err)
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

// runCertfolds runs certfolds with args and returns what it printed to stdout.
func runCertfolds(t *testing.T, args ...string) string {
	t.Helper()
	out, err := runCertfoldsErr(t, args...)
	if err != nil {
		t.Fatalf("certfolds %s: %v", strings.Join(args, " "), err)
	}
	return out
}

// runCertfoldsErr runs certfolds with args and returns what it printed to stdout
// and its error.
func runCertfoldsErr(t *testing.T, args ...string) (string, error) {
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
	return string(out), runErr
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

	table := runCertfolds(t, "--ipc", socket, "cert", "list")
	wantRows := [][]string{
		{"NAME", "CA", "DOMAINS", "STATE", "NOT", "AFTER", "RENEW", "AT"},
		{"mail", "le", "mail.example.com", "backoff", "-", "-"},
		{"api-prod", "le", "api.example.com", "valid", notAfter.Local().Format("2006-01-02"), renewAt.Local().Format("2006-01-02"), "(ari)"},
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
	sameJSON(runCertfolds(t, "--ipc", socket, "--json", "cert", "list"), "["+mailJSON+","+apiJSON+"]")
	sameJSON(runCertfolds(t, "--ipc", socket, "--json", "cert", "show", "mail"), mailJSON)
	sameJSON(runCertfolds(t, "--ipc", socket, "--json", "cert", "show", "api-prod"), apiJSON)

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
			"Next Attempt: " + nextAttempt.Local().Format("2006-01-02 15:04:05 -07:00") + "\n",
		"api-prod": "Name:         api-prod\n" +
			"CA:           le\n" +
			"Domains:      api.example.com\n" +
			"Subscribers:  web-1, web-2\n" +
			"Not After:    " + notAfter.Local().Format("2006-01-02") + "\n" +
			"Renew At:     " + renewAt.Local().Format("2006-01-02 15:04:05 -07:00") + " (ari)\n" +
			"State:        valid\n" +
			"Failures:     0\n" +
			"Last Error:   -\n" +
			"Next Attempt: -\n",
	}
	for name, want := range wantShow {
		if got := runCertfolds(t, "--ipc", socket, "cert", "show", name); got != want {
			t.Errorf("cert show %s printed:\n%s\nwant:\n%s", name, got, want)
		}
	}
}
