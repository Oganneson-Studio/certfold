package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Oganneson-Studio/sigil/internal/config"
)

const initialRuntimeConfig = `server:
  listen: ":8443"
  public_url: "https://sigil.example.com:8443"
  data_dir: "/var/lib/sigil"
  ipc_socket: "/var/run/sigil/sigils.sock"
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
clients:
  - name: "web-1"
    push_endpoint: "https://web-1.example.com/push"
    push_token: "0123456789abcdef0123456789abcdef"
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
	runtime := newServerConfigRuntime(path, initial)

	nextRaw := strings.NewReplacer(
		"ops@example.com", "security@example.com",
		"api.example.com", "api-v2.example.com",
		"subscribers: [\"web-1\"]", "subscribers: [\"web-1\", \"web-2\"]",
		"web-1.example.com/push", "push.example.com/notify",
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
	if got.Clients[0].PushEndpoint != "https://push.example.com/notify" {
		t.Fatalf("push route = %q", got.Clients[0].PushEndpoint)
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
		{name: "data dir", old: `data_dir: "/var/lib/sigil"`, new: `data_dir: "/srv/sigil"`, want: "server.data_dir"},
		{name: "ipc socket", old: `ipc_socket: "/var/run/sigil/sigils.sock"`, new: `ipc_socket: "/tmp/sigils.sock"`, want: "server.ipc_socket"},
		{name: "public URL", old: `public_url: "https://sigil.example.com:8443"`, new: `public_url: "https://new.example.com:8443"`, want: "server.public_url"},
		{
			name: "TLS files",
			old:  `  ipc_socket: "/var/run/sigil/sigils.sock"`,
			new:  "  ipc_socket: \"/var/run/sigil/sigils.sock\"\n  tls_cert_file: \"/etc/sigil/cert.pem\"\n  tls_key_file: \"/etc/sigil/key.pem\"",
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
			runtime := newServerConfigRuntime(path, initial)
			writeRuntimeConfig(t, path, strings.Replace(initialRuntimeConfig, tt.old, tt.new, 1))

			err := runtime.Reload(context.Background())
			if err == nil || !strings.Contains(err.Error(), tt.want) || !strings.Contains(err.Error(), "restart sigils") {
				t.Fatalf("Reload error = %v", err)
			}
			if runtime.Current() != initial {
				t.Fatal("rejected reload changed the published generation")
			}
		})
	}
}

func TestServerConfigRuntimeReloadWithUnchangedDNSResolversPublishes(t *testing.T) {
	withResolvers := strings.Replace(initialRuntimeConfig, `  default_ca: "le"`,
		"  default_ca: \"le\"\n  dns_resolvers: [\"1.1.1.1\", \"8.8.8.8:53\"]", 1)
	path := filepath.Join(t.TempDir(), "server.yaml")
	initial := parseRuntimeConfig(t, withResolvers)
	runtime := newServerConfigRuntime(path, initial)
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
	runtime := newServerConfigRuntime(path, initial)
	writeRuntimeConfig(t, path, "server: [invalid")

	if err := runtime.Reload(context.Background()); err == nil {
		t.Fatal("Reload accepted invalid YAML")
	}
	if runtime.Current() != initial {
		t.Fatal("invalid reload changed the published generation")
	}
}
