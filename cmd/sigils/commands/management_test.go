package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/ipc"
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

	clientJSON, err := json.Marshal(newClientDetails(&ipc.ClientInfo{
		Name: "web-1", PushConfigured: true,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(clientJSON)), "push_token") || !strings.Contains(string(clientJSON), `"push_configured":true`) {
		t.Fatalf("client JSON leaked push token: %s", clientJSON)
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
    renew_days_before: 30
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
	stubServerReloader(t, nil, errors.New("daemon is not running"))
	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"--config", path, "cert", "add", "api-prod",
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
