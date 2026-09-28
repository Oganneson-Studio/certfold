package client

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/renewal"
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
	cfg := buildTestCfg(t, "https://sigil.example.test")
	dir := t.TempDir()
	// a has two outputs and an on_change program, c one output; client.yaml
	// configures nothing for b and d.
	fullchainOutput(cfg, dir, "a", "/usr/sbin/reload")
	outputs := cfg.Certificates["a"]
	outputs.Outputs = append(outputs.Outputs, config.OutputSpec{Format: "pem-key", Path: filepath.Join(dir, "a.key")})
	cfg.Certificates["a"] = outputs
	fullchainOutput(cfg, dir, "c")

	var want []CertStatus
	stored := make(map[string]storedCert)
	for _, name := range []string{"a", "b", "c", "d"} {
		bundle := newTestBundle(t, name)
		stored[name] = storedCert{Fingerprint: bundle.Fingerprint, FullchainPEM: bundle.FullchainPEM, KeyPEM: bundle.KeyPEM, HookPending: name == "a"}
		renewAt, err := renewal.RenewAt(bundle.FullchainPEM)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, CertStatus{Name: name, Fingerprint: bundle.Fingerprint, NotAfter: bundleNotAfter(t, bundle), RenewAt: renewAt})
	}
	want[0].Outputs, want[0].OnChange, want[0].HookPending = 2, true, true
	want[2].Outputs = 1

	// certs.json lists the certificates in reverse name order. Go iterates a
	// map of up to 8 entries in a rotation of the order they were added, and
	// no rotation of d, c, b, a is in name order: a status that is not sorted
	// fails every run. saveStore would write the names in order, which the
	// rotation keeps for most starting points.
	var file strings.Builder
	file.WriteString(`{"certs":{`)
	for i, name := range []string{"d", "c", "b", "a"} {
		entry, err := json.Marshal(stored[name])
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 {
			file.WriteString(",")
		}
		fmt.Fprintf(&file, "%q:%s", name, entry)
	}
	file.WriteString("}}")
	if err := os.WriteFile(filepath.Join(cfg.Client.DataDir, storeFileName), []byte(file.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	c := newTestClient(t, cfg)
	if got := c.Status().Certs; !slices.Equal(got, want) {
		t.Fatalf("certificates:\n got %+v\nwant %+v", got, want)
	}
}

// TestStatusDoesNotWaitForPullMu covers the status while a round, fetch or
// reload holds pullMu, which it keeps while on_change programs run for up to
// 2 minutes each: Status answers at once.
func TestStatusDoesNotWaitForPullMu(t *testing.T) {
	c := newTestClient(t, buildTestCfg(t, "https://sigil.example.test"))
	c.pullMu.Lock()
	defer c.pullMu.Unlock()

	answered := make(chan struct{})
	go func() {
		c.Status()
		close(answered)
	}()
	select {
	case <-answered:
	case <-time.After(5 * time.Second):
		t.Fatal("Status waited for pullMu")
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
