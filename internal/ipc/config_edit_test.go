package ipc

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/Oganneson-Studio/sigil/internal/config"
)

// The certificate edits of server.yaml answer with the file the daemon
// changed, and with its reason when it refuses: 404 for a certificate that
// is not configured, as for a client or a token, and 422 otherwise.
func TestCertificateEditsOfTheConfiguration(t *testing.T) {
	var added config.CertificateSpec
	var removed string
	var refusal error
	h := &ipcHandlers{deps: ServerDeps{Server: &ServerControlDeps{
		ConfigPath: "/etc/sigil/server.yaml",
		AddCertificate: func(_ context.Context, spec config.CertificateSpec) error {
			added = spec
			return refusal
		},
		RemoveCertificate: func(_ context.Context, name string) error {
			removed = name
			return refusal
		},
	}}}
	ts := httptest.NewServer(buildIPCRouter(h))
	defer ts.Close()
	c := newTestClient(ts)
	ctx := context.Background()

	req := AddCertificateRequest{
		Name: "api-prod", Domains: []string{"api.example.com"}, CA: "le",
		DNSProvider: "cf", KeyType: "ec384", Subscribers: []string{"web-1"},
	}
	changed, err := c.AddCertificate(ctx, req)
	if err != nil || changed.ConfigPath != "/etc/sigil/server.yaml" {
		t.Fatalf("AddCertificate = %+v, %v; want the daemon's server.yaml", changed, err)
	}
	want := config.CertificateSpec{
		Name: "api-prod", Domains: []string{"api.example.com"}, CA: "le",
		DNSProvider: "cf", KeyType: "ec384", Subscribers: []string{"web-1"},
	}
	if !reflect.DeepEqual(added, want) {
		t.Errorf("the daemon was asked to add %+v, want %+v", added, want)
	}
	// Removed as typed, even with a character that would end the path.
	changed, err = c.RemoveCertificate(ctx, "api?prod")
	if err != nil || changed.ConfigPath != "/etc/sigil/server.yaml" || removed != "api?prod" {
		t.Fatalf("RemoveCertificate = %+v, %v, removing %q; want api?prod removed from the daemon's server.yaml", changed, err, removed)
	}

	refusal = errors.New("cannot hot reload changes to server.listen; restart sigils to apply them")
	for what, call := range map[string]func() (*ConfigChangeResponse, error){
		"AddCertificate":    func() (*ConfigChangeResponse, error) { return c.AddCertificate(ctx, req) },
		"RemoveCertificate": func() (*ConfigChangeResponse, error) { return c.RemoveCertificate(ctx, "api-prod") },
	} {
		if _, err := call(); err == nil || !strings.HasSuffix(err.Error(), "server returned 422: "+refusal.Error()) {
			t.Errorf("%s error = %v, want the refusal with 422", what, err)
		}
	}
	refusal = fmt.Errorf("cert %q %w", "api-prod", config.ErrCertificateNotFound)
	if _, err := c.RemoveCertificate(ctx, "api-prod"); err == nil || !strings.HasSuffix(err.Error(), `server returned 404: cert "api-prod" not found`) {
		t.Errorf("RemoveCertificate error = %v, want the refusal with 404", err)
	}
}

func TestCertificateEditsRejectUnavailable(t *testing.T) {
	ts := httptest.NewServer(buildIPCRouter(&ipcHandlers{deps: ServerDeps{Server: &ServerControlDeps{}}}))
	defer ts.Close()
	c := newTestClient(ts)
	if _, err := c.AddCertificate(context.Background(), AddCertificateRequest{Name: "api-prod"}); err == nil || !strings.Contains(err.Error(), "501") {
		t.Errorf("AddCertificate error = %v, want 501", err)
	}
	if _, err := c.RemoveCertificate(context.Background(), "api-prod"); err == nil || !strings.Contains(err.Error(), "501") {
		t.Errorf("RemoveCertificate error = %v, want 501", err)
	}
}
