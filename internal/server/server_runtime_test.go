package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Oganneson-Studio/sigil/internal/config"
)

// absPath makes path, a Unix absolute path, absolute on the OS running the
// test: on Windows it puts it on drive C:. Windows takes the slashes of
// C:/var/lib for separators, and YAML reads slashes as they are in any
// quoting, unlike backslashes.
func absPath(path string) string {
	if runtime.GOOS == "windows" {
		return "C:" + path
	}
	return path
}

// ipcSocketLine is the line of initialRuntimeConfig that sets
// server.ipc_socket.
var ipcSocketLine = `  ipc_socket: "` + absPath("/var/run/sigil/sigils.sock") + `"`

// tlsFileLines set server.tls_cert_file and server.tls_key_file.
var tlsFileLines = "\n  tls_cert_file: \"" + absPath("/etc/sigil/cert.pem") + "\"\n  tls_key_file: \"" + absPath("/etc/sigil/key.pem") + "\""

var initialRuntimeConfig = `server:
  listen: ":8443"
  public_url: "https://sigil.example.com:8443"
  data_dir: "` + absPath("/var/lib/sigil") + `"
` + ipcSocketLine + `
acme:
  email: "ops@example.com"
  default_ca: "le"
  cas:
    le:
      directory: "https://acme.example.com/directory"
dns_providers:
  cf:
    type: "cloudflare"
    api_token: "initial-secret"
certificates:
  - name: "api-prod"
    domains: ["api.example.com"]
    ca: "le"
    dns_provider: "cf"
    subscribers: ["web-1"]
`

func parseRuntimeConfig(t *testing.T, raw string) *config.ServerConfig {
	t.Helper()
	cfg, err := config.ParseServer([]byte(raw))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	return cfg
}

func writeRuntimeConfig(t *testing.T, path, raw string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestServerConfigRuntimeReloadPublishesMutableGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	initial := parseRuntimeConfig(t, initialRuntimeConfig)
	notified := 0
	runtime := newServerConfigRuntime(path, initial, func() { notified++ }, publishNow)

	nextRaw := strings.NewReplacer(
		"ops@example.com", "security@example.com",
		"api.example.com", "api-v2.example.com",
		"subscribers: [\"web-1\"]", "subscribers: [\"web-1\", \"web-2\"]",
	).Replace(initialRuntimeConfig)
	writeRuntimeConfig(t, path, nextRaw)

	if err := runtime.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	got := runtime.Current()
	if got == initial {
		t.Fatal("reload did not publish a new configuration generation")
	}
	if got.ACME.Email != "security@example.com" {
		t.Fatalf("ACME email = %q", got.ACME.Email)
	}
	if got.Certificates[0].Domains[0] != "api-v2.example.com" || len(got.Certificates[0].Subscribers) != 2 {
		t.Fatalf("certificate config was not reloaded: %+v", got.Certificates[0])
	}
	if notified != 1 {
		t.Fatalf("reload notified %d times, want once", notified)
	}
}

// publisherFunc stands in for the scheduler's PublishConfig.
type publisherFunc func(context.Context, func()) error

func (f publisherFunc) PublishConfig(ctx context.Context, publish func()) error {
	return f(ctx, publish)
}

// publishNow publishes at once, as the scheduler does when no issuance
// stores its outcome meanwhile.
var publishNow = publisherFunc(func(_ context.Context, publish func()) error {
	publish()
	return nil
})

func TestServerConfigRuntimeNotifiesAfterPublishing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	initial := parseRuntimeConfig(t, initialRuntimeConfig)
	writeRuntimeConfig(t, path, strings.Replace(initialRuntimeConfig, "ops@example.com", "security@example.com", 1))

	var runtime *serverConfigRuntime
	notified := 0
	notify := func() {
		notified++
		if runtime.Current() == initial {
			t.Error("notified before the new generation was published")
		}
	}

	failing := publisherFunc(func(context.Context, func()) error {
		return errors.New("clear issuance backoff: database is locked")
	})
	runtime = newServerConfigRuntime(path, initial, notify, failing)
	if err := runtime.Reload(context.Background()); err == nil {
		t.Fatal("Reload ignored the publisher's error")
	}
	if notified != 0 {
		t.Fatalf("a reload that was not published notified %d times", notified)
	}

	publishing := publisherFunc(func(_ context.Context, publish func()) error {
		publish()
		if notified != 0 {
			t.Error("notified from the publish callback, which may only publish")
		}
		return nil
	})
	runtime = newServerConfigRuntime(path, initial, notify, publishing)
	if err := runtime.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if notified != 1 {
		t.Fatalf("reload notified %d times, want once", notified)
	}
}

func TestServerConfigRuntimeRejectsImmutableChangesWithoutPublishing(t *testing.T) {
	tests := []struct {
		name string
		old  string
		new  string
		want string
	}{
		{name: "listen", old: `listen: ":8443"`, new: `listen: ":9443"`, want: "server.listen"},
		{name: "data dir", old: absPath("/var/lib/sigil"), new: absPath("/srv/sigil"), want: "server.data_dir"},
		{name: "ipc socket", old: absPath("/var/run/sigil/sigils.sock"), new: absPath("/tmp/sigils.sock"), want: "server.ipc_socket"},
		{name: "public URL", old: `public_url: "https://sigil.example.com:8443"`, new: `public_url: "https://new.example.com:8443"`, want: "server.public_url"},
		{
			name: "TLS files",
			old:  ipcSocketLine,
			new:  ipcSocketLine + tlsFileLines,
			want: "server.tls_cert_file",
		},
		{
			name: "DNS resolvers",
			old:  `  default_ca: "le"`,
			new:  "  default_ca: \"le\"\n  dns_resolvers: [\"1.1.1.1\"]",
			want: "acme.dns_resolvers",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "server.yaml")
			initial := parseRuntimeConfig(t, initialRuntimeConfig)
			notified := 0
			runtime := newServerConfigRuntime(path, initial, func() { notified++ }, publishNow)
			writeRuntimeConfig(t, path, strings.Replace(initialRuntimeConfig, tt.old, tt.new, 1))

			err := runtime.Reload(context.Background())
			if err == nil || !strings.Contains(err.Error(), tt.want) || !strings.Contains(err.Error(), "restart sigils") {
				t.Fatalf("Reload error = %v", err)
			}
			if runtime.Current() != initial {
				t.Fatal("rejected reload changed the published generation")
			}
			if notified != 0 {
				t.Fatalf("rejected reload notified %d times", notified)
			}
		})
	}
}

// A reload that changes tls_key_file alone is refused like one that changes
// tls_cert_file: the TLS files are fixed at startup. The "TLS files" case
// above adds both and checks for tls_cert_file only.
func TestServerConfigRuntimeRejectsTLSKeyFileChangeAlone(t *testing.T) {
	withFiles := strings.Replace(initialRuntimeConfig, ipcSocketLine, ipcSocketLine+tlsFileLines, 1)
	path := filepath.Join(t.TempDir(), "server.yaml")
	initial := parseRuntimeConfig(t, withFiles)
	notified := 0
	runtime := newServerConfigRuntime(path, initial, func() { notified++ }, publishNow)
	writeRuntimeConfig(t, path, strings.Replace(withFiles, "/etc/sigil/key.pem", "/etc/sigil/new-key.pem", 1))

	err := runtime.Reload(context.Background())
	if err == nil || !strings.Contains(err.Error(), "server.tls_key_file") || strings.Contains(err.Error(), "server.tls_cert_file") {
		t.Fatalf("Reload error = %v, want one naming server.tls_key_file only", err)
	}
	if runtime.Current() != initial || notified != 0 {
		t.Fatal("a reload that changes tls_key_file was published")
	}
}

func TestServerConfigRuntimeReloadWithUnchangedDNSResolversPublishes(t *testing.T) {
	withResolvers := strings.Replace(initialRuntimeConfig, `  default_ca: "le"`,
		"  default_ca: \"le\"\n  dns_resolvers: [\"1.1.1.1\", \"8.8.8.8:53\"]", 1)
	path := filepath.Join(t.TempDir(), "server.yaml")
	initial := parseRuntimeConfig(t, withResolvers)
	runtime := newServerConfigRuntime(path, initial, func() {}, publishNow)
	writeRuntimeConfig(t, path, strings.Replace(withResolvers, "ops@example.com", "security@example.com", 1))

	if err := runtime.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := runtime.Current(); got == initial || got.ACME.Email != "security@example.com" {
		t.Fatal("reload with unchanged dns_resolvers did not publish the new generation")
	}
}

func TestServerConfigRuntimeInvalidReloadKeepsPreviousGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	initial := parseRuntimeConfig(t, initialRuntimeConfig)
	notified := 0
	runtime := newServerConfigRuntime(path, initial, func() { notified++ }, publishNow)
	writeRuntimeConfig(t, path, "server: [invalid")

	if err := runtime.Reload(context.Background()); err == nil {
		t.Fatal("Reload accepted invalid YAML")
	}
	if runtime.Current() != initial {
		t.Fatal("invalid reload changed the published generation")
	}
	if notified != 0 {
		t.Fatalf("invalid reload notified %d times", notified)
	}
}
