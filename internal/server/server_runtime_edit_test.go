package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Oganneson-Studio/certfold/internal/ca"
	"github.com/Oganneson-Studio/certfold/internal/config"
	"github.com/Oganneson-Studio/certfold/internal/ipc"
)

// wwwSpec is a certificate that initialRuntimeConfig admits.
var wwwSpec = config.CertificateSpec{Name: "www", Domains: []string{"www.example.com"}, DNSProvider: "cf", KeyType: "ec256"}

// certificateNames returns the names of the certificates of cfg.
func certificateNames(cfg *config.ServerConfig) []string {
	var names []string
	for _, spec := range cfg.Certificates {
		names = append(names, spec.Name)
	}
	return names
}

// assertCertificates checks that both the running configuration and
// server.yaml hold the named certificates.
func assertCertificates(t *testing.T, runtime *serverConfigRuntime, path string, want ...string) {
	t.Helper()
	onDisk, err := config.LoadServer(path)
	if err != nil {
		t.Fatal(err)
	}
	for what, cfg := range map[string]*config.ServerConfig{"running": runtime.Current(), "server.yaml": onDisk} {
		if got := strings.Join(certificateNames(cfg), " "); got != strings.Join(want, " ") {
			t.Errorf("%s certificates = %q, want %q", what, got, want)
		}
	}
}

func TestAddAndRemoveCertificateWriteAndApplyTheConfiguration(t *testing.T) {
	events := setupLogs(t, io.Discard).Events
	path := filepath.Join(t.TempDir(), "server.yaml")
	writeRuntimeConfig(t, path, initialRuntimeConfig)
	notified := 0
	runtime := newServerConfigRuntime(path, parseRuntimeConfig(t, initialRuntimeConfig), func() { notified++ }, publishNow)
	ctx := context.Background()

	if err := runtime.AddCertificate(ctx, wwwSpec); err != nil {
		t.Fatalf("AddCertificate: %v", err)
	}
	assertCertificates(t, runtime, path, "api-prod", "www")
	if spec := runtime.Current().Certificates[1]; spec.CA != "le" {
		t.Errorf("added certificate has CA %q, want acme.default_ca le", spec.CA)
	}
	if err := runtime.RemoveCertificate(ctx, "api-prod"); err != nil {
		t.Fatalf("RemoveCertificate: %v", err)
	}
	assertCertificates(t, runtime, path, "www")
	if notified != 2 {
		t.Errorf("the edits notified %d times, want once each", notified)
	}
	assertTLSEvents(t, events,
		"INFO certificate added to the configuration cert=www",
		"INFO certificate removed from the configuration cert=api-prod")
}

// A change is written only if the daemon would apply the file it makes.
func TestCertificateEditsThatCannotApplyLeaveTheFile(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name   string
		onDisk string // server.yaml as it is before the edit
		edit   func(context.Context, *serverConfigRuntime) error
		ctx    context.Context
		want   string
	}{
		{
			name: "invalid certificate",
			edit: func(ctx context.Context, r *serverConfigRuntime) error {
				spec := wwwSpec
				spec.DNSProvider = "missing"
				return r.AddCertificate(ctx, spec)
			},
			want: `references unknown DNS provider "missing"`,
		},
		{
			name: "certificate not configured",
			edit: func(ctx context.Context, r *serverConfigRuntime) error { return r.RemoveCertificate(ctx, "www") },
			want: `cert "www" not found`,
		},
		{
			// An operator edited server.yaml by hand and has not restarted.
			name:   "file awaiting a restart",
			onDisk: strings.Replace(initialRuntimeConfig, `listen: ":8443"`, `listen: ":9443"`, 1),
			edit:   func(ctx context.Context, r *serverConfigRuntime) error { return r.AddCertificate(ctx, wwwSpec) },
			want:   "cannot hot reload changes to server.listen; restart certfolds to apply them",
		},
		{
			name: "caller gone",
			edit: func(ctx context.Context, r *serverConfigRuntime) error { return r.AddCertificate(ctx, wwwSpec) },
			ctx:  cancelled,
			want: context.Canceled.Error(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			onDisk := tt.onDisk
			if onDisk == "" {
				onDisk = initialRuntimeConfig
			}
			ctx := tt.ctx
			if ctx == nil {
				ctx = context.Background()
			}
			path := filepath.Join(t.TempDir(), "server.yaml")
			writeRuntimeConfig(t, path, onDisk)
			initial := parseRuntimeConfig(t, initialRuntimeConfig)
			notified := 0
			runtime := newServerConfigRuntime(path, initial, func() { notified++ }, publishNow)

			if err := tt.edit(ctx, runtime); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("edit error = %v, want %s", err, tt.want)
			}
			assertFile(t, path, onDisk)
			if runtime.Current() != initial || notified != 0 {
				t.Fatal("a refused edit was published")
			}
		})
	}
}

// Once the file is written, a failure to apply it puts the file back.
func TestCertificateEditRestoresTheFileWhenApplyingFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	writeRuntimeConfig(t, path, initialRuntimeConfig)
	initial := parseRuntimeConfig(t, initialRuntimeConfig)
	var onDisk []byte
	failing := publisherFunc(func(context.Context, func()) error {
		onDisk, _ = os.ReadFile(path)
		return errors.New("clear issuance backoff: database is locked")
	})
	runtime := newServerConfigRuntime(path, initial, func() { t.Error("a failed edit notified") }, failing)

	if err := runtime.AddCertificate(context.Background(), wwwSpec); err == nil || err.Error() != "clear issuance backoff: database is locked" {
		t.Fatalf("AddCertificate error = %v, want the publisher's", err)
	}
	if !strings.Contains(string(onDisk), "www.example.com") {
		t.Fatalf("server.yaml was not written before it was applied:\n%s", onDisk)
	}
	assertFile(t, path, initialRuntimeConfig)
	if runtime.Current() != initial {
		t.Fatal("a failed edit changed the running configuration")
	}
}

// Once the file is written, the caller going away, such as a CLI that is
// interrupted, does not keep it from being applied: the file would otherwise
// hold a change the daemon does not run.
func TestCertificateEditIsAppliedAfterItsCallerLeaves(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	writeRuntimeConfig(t, path, initialRuntimeConfig)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Like the scheduler's PublishConfig, it fails once its ctx is done.
	leaving := publisherFunc(func(ctx context.Context, publish func()) error {
		cancel()
		if err := ctx.Err(); err != nil {
			return err
		}
		publish()
		return nil
	})
	runtime := newServerConfigRuntime(path, parseRuntimeConfig(t, initialRuntimeConfig), func() {}, leaving)

	if err := runtime.AddCertificate(ctx, wwwSpec); err != nil {
		t.Fatalf("AddCertificate: %v", err)
	}
	assertCertificates(t, runtime, path, "api-prod", "www")
}

// The edit replaces the file a symbolic link points to, and keeps the link.
func TestCertificateEditFollowsASymbolicLink(t *testing.T) {
	target := filepath.Join(t.TempDir(), "server.yaml")
	writeRuntimeConfig(t, target, initialRuntimeConfig)
	linkDir := t.TempDir()
	link := filepath.Join(linkDir, "server.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create a symbolic link: %v", err)
	}
	runtime := newServerConfigRuntime(link, parseRuntimeConfig(t, initialRuntimeConfig), func() {}, publishNow)

	if err := runtime.AddCertificate(context.Background(), wwwSpec); err != nil {
		t.Fatalf("AddCertificate: %v", err)
	}
	if got, err := os.Readlink(link); err != nil || got != target {
		t.Fatalf("link points to %q (%v), want %q", got, err, target)
	}
	assertCertificates(t, runtime, target, "api-prod", "www")
	for _, dir := range []string{filepath.Dir(target), linkDir} {
		if entries, _ := os.ReadDir(dir); len(entries) != 1 {
			t.Errorf("%s holds %d entries after the edit, want only server.yaml", dir, len(entries))
		}
	}
}

// The daemon serves the certificate edits of its server.yaml over IPC.
func TestRunEditsItsConfigurationOverIPC(t *testing.T) {
	dataDir := privateDir(t)
	miniCA, err := ca.Bootstrap(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	port, socket := freeTCPPort(t), testIPCSocket(t)
	path := filepath.Join(privateDir(t), "server.yaml")
	// Nothing listens on the CA's port, so the issuance of the certificate
	// added fails at once.
	writeRuntimeConfig(t, path, fmt.Sprintf(`server:
  listen: "127.0.0.1:%d"
  data_dir: %q
  ipc_socket: %q
acme:
  email: "ops@example.com"
  default_ca: "le"
  cas:
    le:
      directory: "https://127.0.0.1:%d/dir"
dns_providers:
  cf:
    type: "cloudflare"
    api_token: "never-used"
certificates: []
`, port, dataDir, socket, freeTCPPort(t)))
	logs := setupLogs(t, io.Discard)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- Run(ctx, path, logs) }()
	waitServing(t, miniCA, port, result)
	c, err := ipc.NewClient(socket)
	if err != nil {
		skipWithoutPipeAccess(t, err)
		t.Fatal(err)
	}

	changed, err := c.AddCertificate(ctx, ipc.AddCertificateRequest{
		Name: "api-prod", Domains: []string{"api.example.com"}, DNSProvider: "cf", KeyType: "ec256",
	})
	if err != nil || changed.ConfigPath != path {
		t.Fatalf("AddCertificate = %+v, %v; want %s changed", changed, err, path)
	}
	assertListed(t, c, path, "api-prod")
	if _, err := c.RemoveCertificate(ctx, "api-prod"); err != nil {
		t.Fatalf("RemoveCertificate: %v", err)
	}
	assertListed(t, c, path)

	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Run returned %v after cancellation, want nil", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

// assertListed checks that the daemon c reaches lists the named
// certificates, and that server.yaml at path holds them.
func assertListed(t *testing.T, c *ipc.Client, path string, want ...string) {
	t.Helper()
	certs, err := c.ListCerts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var listed []string
	for _, cert := range certs {
		listed = append(listed, cert.Name)
	}
	onDisk, err := config.LoadServer(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(listed, " ") != strings.Join(want, " ") || strings.Join(certificateNames(onDisk), " ") != strings.Join(want, " ") {
		t.Errorf("listed %q, server.yaml holds %q; want %q", listed, certificateNames(onDisk), want)
	}
}

func assertFile(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(want)) {
		t.Fatalf("%s changed:\n%s", path, got)
	}
}
