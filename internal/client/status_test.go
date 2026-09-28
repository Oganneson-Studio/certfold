package client

import (
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/pkg/proto"
)

// statusFingerprints maps the name of each certificate status lists to its
// fingerprint.
func statusFingerprints(status RuntimeStatus) map[string]string {
	out := make(map[string]string, len(status.Certs))
	for _, cert := range status.Certs {
		out[cert.Name] = cert.Fingerprint
	}
	return out
}

func bundleNotAfter(t *testing.T, bundle *proto.CertBundle) time.Time {
	t.Helper()
	block, _ := pem.Decode([]byte(bundle.FullchainPEM))
	if block == nil {
		t.Fatalf("bundle %s holds no PEM block", bundle.Name)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return leaf.NotAfter
}

func TestStatusDescribesStoredCertificates(t *testing.T) {
	a, b := newTestBundle(t, "a"), newTestBundle(t, "b")
	cfg := buildTestCfg(t, "https://sigil.example.test")
	dir := t.TempDir()
	fullchainOutput(cfg, dir, "a", "/usr/sbin/reload")
	outputs := cfg.Certificates["a"]
	outputs.Outputs = append(outputs.Outputs, config.OutputSpec{Format: "pem-key", Path: filepath.Join(dir, "a.key")})
	cfg.Certificates["a"] = outputs
	if err := saveStore(cfg.Client.DataDir, map[string]storedCert{
		"b": {Fingerprint: b.Fingerprint, FullchainPEM: b.FullchainPEM, KeyPEM: b.KeyPEM},
		"a": {Fingerprint: a.Fingerprint, FullchainPEM: a.FullchainPEM, KeyPEM: a.KeyPEM, HookPending: true},
	}); err != nil {
		t.Fatal(err)
	}

	c := newTestClient(t, cfg)
	want := []CertStatus{
		{Name: "a", Fingerprint: a.Fingerprint, NotAfter: bundleNotAfter(t, a), Outputs: 2, OnChange: true, HookPending: true},
		// client.yaml configures nothing for b.
		{Name: "b", Fingerprint: b.Fingerprint, NotAfter: bundleNotAfter(t, b)},
	}
	if got := c.Status().Certs; !slices.Equal(got, want) {
		t.Fatalf("certificates:\n got %+v\nwant %+v", got, want)
	}
}

// TestStatusFollowsReloadAtOnce covers the outputs and on_change program a
// reload configures: the status shows them when Reload returns, before any
// round of the loop.
func TestStatusFollowsReloadAtOnce(t *testing.T) {
	bundle := newTestBundle(t, "api-prod")
	cfg := buildTestCfg(t, "https://sigil.example.test")
	seedStore(t, cfg.Client.DataDir, bundle)
	c := newTestClient(t, cfg)
	c.hook = (&fakeHook{}).run
	if got := c.Status().Certs; len(got) != 1 || got[0].Outputs != 0 || got[0].OnChange {
		t.Fatalf("certificates before the reload = %+v", got)
	}

	updated := *cfg
	updated.Certificates = map[string]config.CertificateOutputs{}
	fullchainOutput(&updated, t.TempDir(), "api-prod", "/usr/sbin/reload")
	if err := c.Reload(&updated); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	got := c.Status().Certs
	if len(got) != 1 || got[0].Name != "api-prod" || got[0].Outputs != 1 || !got[0].OnChange || got[0].HookPending {
		t.Fatalf("certificates after the reload = %+v, want api-prod with 1 output and on_change", got)
	}
}
