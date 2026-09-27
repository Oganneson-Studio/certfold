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

type recordingImmediateRenewer struct {
	cfg   *config.ServerConfig
	spec  config.CertificateSpec
	calls int
	err   error
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

func (r *recordingImmediateRenewer) RenewNow(_ context.Context, cfg *config.ServerConfig, spec config.CertificateSpec) error {
	r.calls++
	r.cfg = cfg
	r.spec = spec
	return r.err
}

func TestRenewConfiguredCertificateUsesLiveSpec(t *testing.T) {
	cfg := &config.ServerConfig{Certificates: []config.CertificateSpec{{
		Name: "api-prod", Domains: []string{"api.example.com"}, CA: "le",
	}}}
	r := &recordingImmediateRenewer{}
	if err := renewConfiguredCertificate(context.Background(), cfg, r, "api-prod"); err != nil {
		t.Fatal(err)
	}
	if r.calls != 1 || r.cfg != cfg || r.spec.Name != "api-prod" {
		t.Fatalf("renewer calls = %d, spec = %+v", r.calls, r.spec)
	}

	if err := renewConfiguredCertificate(context.Background(), cfg, r, "API-PROD"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing cert error = %v", err)
	}
	if r.calls != 1 {
		t.Fatalf("missing cert triggered renewal; calls = %d", r.calls)
	}
}

func TestRenewConfiguredCertificatePropagatesIssuerFailure(t *testing.T) {
	want := errors.New("acme failed")
	r := &recordingImmediateRenewer{err: want}
	cfg := &config.ServerConfig{Certificates: []config.CertificateSpec{{Name: "api-prod"}}}
	if err := renewConfiguredCertificate(context.Background(), cfg, r, "api-prod"); !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
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
