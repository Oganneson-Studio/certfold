package output

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/Oganneson-Studio/sigil/internal/config"
)

// makeBundle creates a self-signed cert + key for testing.
func makeBundle(t *testing.T) *CertBundle {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return &CertBundle{
		CertPEM:  certPEM,
		ChainPEM: nil,
		KeyPEM:   keyPEM,
	}
}

func TestEncode_PemCert(t *testing.T) {
	b := makeBundle(t)
	spec := config.OutputSpec{Format: "pem-cert"}
	data, err := encode(b, spec)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("expected CERTIFICATE PEM block, got %v", block)
	}
}

func TestEncode_PemKey(t *testing.T) {
	b := makeBundle(t)
	spec := config.OutputSpec{Format: "pem-key"}
	data, err := encode(b, spec)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("expected PEM key block")
	}
}

func TestEncode_PemFullchain(t *testing.T) {
	b := makeBundle(t)
	// add a fake chain cert (same cert re-used)
	b.ChainPEM = b.CertPEM
	spec := config.OutputSpec{Format: "pem-fullchain"}
	data, err := encode(b, spec)
	if err != nil {
		t.Fatal(err)
	}
	// Should have two CERTIFICATE blocks
	count := 0
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("expected 2 CERTIFICATE blocks, got %d", count)
	}
}

func TestEncode_PemBundle(t *testing.T) {
	b := makeBundle(t)
	spec := config.OutputSpec{Format: "pem-bundle"}
	data, err := encode(b, spec)
	if err != nil {
		t.Fatal(err)
	}
	// Should contain both cert and key blocks
	hasCert, hasKey := false, false
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			hasCert = true
		}
		if block.Type == "EC PRIVATE KEY" {
			hasKey = true
		}
	}
	if !hasCert || !hasKey {
		t.Fatalf("pem-bundle: hasCert=%v hasKey=%v", hasCert, hasKey)
	}
}

func TestEncode_DER(t *testing.T) {
	b := makeBundle(t)
	spec := config.OutputSpec{Format: "der"}
	data, err := encode(b, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParseCertificate(data); err != nil {
		t.Fatalf("DER output is not a valid certificate: %v", err)
	}
}

func TestEncode_PKCS12(t *testing.T) {
	b := makeBundle(t)
	spec := config.OutputSpec{Format: "pkcs12", Password: "testpass"}
	data, err := encode(b, spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("PKCS12 output is empty")
	}
	// Verify by decoding
	import_pkcs12_decoder(t, data, "testpass")
}

func import_pkcs12_decoder(t *testing.T, data []byte, password string) {
	t.Helper()
	// Basic check: pkcs12 starts with a valid ASN.1 sequence (0x30)
	if len(data) == 0 || data[0] != 0x30 {
		t.Fatalf("PKCS12 data does not start with ASN.1 SEQUENCE tag (got 0x%02x)", data[0])
	}
}

func TestEncode_UnknownFormat(t *testing.T) {
	b := makeBundle(t)
	_, err := encode(b, config.OutputSpec{Format: "jks"})
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
}

func TestOutputMode_SecureDefaults(t *testing.T) {
	tests := []struct {
		format string
		want   int
	}{
		{format: "pem-cert", want: 0o644},
		{format: "pem-fullchain", want: 0o644},
		{format: "der", want: 0o644},
		{format: "pem-key", want: 0o600},
		{format: "pem-bundle", want: 0o600},
		{format: "pkcs12", want: 0o600},
	}
	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			if got := outputMode(config.OutputSpec{Format: tt.format}); got != tt.want {
				t.Fatalf("outputMode(%s) = %#o, want %#o", tt.format, got, tt.want)
			}
		})
	}
	if got := outputMode(config.OutputSpec{Format: "pem-key", Mode: 0o640}); got != 0o640 {
		t.Fatalf("explicit mode = %#o, want 0640", got)
	}
}

// mustReconcile runs Reconcile, fails t on an error, and returns changed.
func mustReconcile(t *testing.T, b *CertBundle, specs ...config.OutputSpec) bool {
	t.Helper()
	changed, err := Reconcile(b, specs)
	if err != nil {
		t.Fatal(err)
	}
	return changed
}

// fileState returns what a rewrite changes about the file at path: renaming a
// new file over it changes the file ID that os.SameFile compares, and the
// modification time. The file is stat'ed through a handle because os.Stat on
// Windows reads the file ID lazily, from the path, when os.SameFile needs it.
func fileState(t *testing.T, path string) os.FileInfo {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return info
}

// checkUntouched fails unless path is still the file fileState saw as before.
func checkUntouched(t *testing.T, path string, before os.FileInfo) {
	t.Helper()
	after := fileState(t, path)
	if !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) {
		t.Errorf("%s was rewritten", path)
	}
}

// checkContent fails unless the output spec describes holds b: the bytes
// encode gives, or for pkcs12 the same key, leaf and chain.
func checkContent(t *testing.T, b *CertBundle, spec config.OutputSpec) {
	t.Helper()
	data, err := os.ReadFile(spec.Path)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Format != "pkcs12" {
		want, err := encode(b, spec)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, want) {
			t.Errorf("%s does not hold the bundle", spec.Path)
		}
		return
	}
	key, leaf, chain, err := pkcs12.DecodeChain(data, spec.Password)
	if err != nil {
		t.Fatalf("decode %s: %v", spec.Path, err)
	}
	wantKey, err := parseKey(b.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	wantLeaf, err := parseCert(b.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	wantChain, err := parseChain(b.ChainPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !wantKey.(*ecdsa.PrivateKey).Equal(key) || !leaf.Equal(wantLeaf) ||
		!slices.EqualFunc(chain, wantChain, (*x509.Certificate).Equal) {
		t.Errorf("%s does not hold the bundle", spec.Path)
	}
}

// checkNoTemps fails if a temporary file is left in any of dirs.
func checkNoTemps(t *testing.T, dirs ...string) {
	t.Helper()
	for _, dir := range dirs {
		if left, err := filepath.Glob(filepath.Join(dir, ".sigil-tmp-*")); err != nil || len(left) != 0 {
			t.Errorf("temporary files left in %s: %v, %v", dir, left, err)
		}
	}
}

// TestReconcile_WritesMissingOutputsOnce writes every format into a directory
// that does not exist yet, then reconciles again: nothing may be rewritten,
// pkcs12 included, although encoding it again would give other bytes.
func TestReconcile_WritesMissingOutputsOnce(t *testing.T) {
	b := makeBundle(t)
	b.ChainPEM = makeBundle(t).CertPEM
	dir := filepath.Join(t.TempDir(), "sub", "nested")
	var specs []config.OutputSpec
	for _, format := range []string{"pem-cert", "pem-key", "pem-fullchain", "pem-bundle", "der", "pkcs12"} {
		specs = append(specs, config.OutputSpec{Format: format, Path: filepath.Join(dir, format), Password: "testpass"})
	}

	if !mustReconcile(t, b, specs...) {
		t.Fatal("missing outputs reported no change")
	}
	before := make([]os.FileInfo, len(specs))
	for i, spec := range specs {
		checkContent(t, b, spec)
		before[i] = fileState(t, spec.Path)
	}

	if mustReconcile(t, b, specs...) {
		t.Error("outputs that match reported a change")
	}
	for i, spec := range specs {
		checkUntouched(t, spec.Path, before[i])
	}
}

// TestReconcile_RewritesModifiedContent covers outputs whose content was
// changed after they were written.
func TestReconcile_RewritesModifiedContent(t *testing.T) {
	b := makeBundle(t)
	dir := t.TempDir()
	specs := []config.OutputSpec{
		{Format: "pem-fullchain", Path: filepath.Join(dir, "fullchain.pem")},
		{Format: "pkcs12", Path: filepath.Join(dir, "cert.p12"), Password: "testpass"},
	}
	mustReconcile(t, b, specs...)
	for _, spec := range specs {
		// An existing file keeps its mode and ACL: only the content differs.
		if err := os.WriteFile(spec.Path, []byte("garbage"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if !mustReconcile(t, b, specs...) {
		t.Fatal("modified outputs reported no change")
	}
	for _, spec := range specs {
		checkContent(t, b, spec)
	}
}

// TestReconcile_PKCS12ComparesDecodedContents covers pkcs12 outputs, whose
// bytes differ on every encoding: they are rewritten only when the password
// or what they hold changes.
func TestReconcile_PKCS12ComparesDecodedContents(t *testing.T) {
	b := makeBundle(t)
	b.ChainPEM = makeBundle(t).CertPEM
	spec := config.OutputSpec{Format: "pkcs12", Path: filepath.Join(t.TempDir(), "cert.p12"), Password: "first"}
	if !mustReconcile(t, b, spec) {
		t.Fatal("a missing output reported no change")
	}
	before := fileState(t, spec.Path)
	if mustReconcile(t, b, spec) {
		t.Fatal("the same material was rewritten")
	}
	checkUntouched(t, spec.Path, before)

	spec.Password = "second"
	if !mustReconcile(t, b, spec) {
		t.Fatal("a new password was not applied")
	}
	checkContent(t, b, spec)

	b.ChainPEM = makeBundle(t).CertPEM
	if !mustReconcile(t, b, spec) {
		t.Fatal("a new chain was not applied")
	}
	checkContent(t, b, spec)

	// Only the key changes, so the leaf and chain cannot tell the bundles
	// apart.
	other := *b
	other.KeyPEM = makeBundle(t).KeyPEM
	if !mustReconcile(t, &other, spec) {
		t.Fatal("a new key was not applied")
	}
	checkContent(t, &other, spec)

	b = makeBundle(t)
	if !mustReconcile(t, b, spec) {
		t.Fatal("a new key and certificate were not applied")
	}
	checkContent(t, b, spec)
}

// TestReconcile_StagesEveryOutputBeforeReplacingAny covers an output that
// cannot be staged: no output of the certificate may be replaced, including
// one staged before it, and no temporary file may be left.
func TestReconcile_StagesEveryOutputBeforeReplacingAny(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "a", "cert.pem")
	// A file where the second output's directory would be.
	blocker := filepath.Join(root, "b", "blocker")
	for _, path := range []string{first, blocker} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	changed, err := Reconcile(makeBundle(t), []config.OutputSpec{
		{Format: "pem-cert", Path: first},
		{Format: "pem-key", Path: filepath.Join(blocker, "key.pem")},
	})
	if err == nil || changed {
		t.Fatalf("Reconcile = %v, %v; want an error and no change", changed, err)
	}
	if data, err := os.ReadFile(first); err != nil || string(data) != "old" {
		t.Fatalf("first output changed: %q, %v", data, err)
	}
	checkNoTemps(t, filepath.Dir(first), filepath.Dir(blocker))
}

// TestReconcile_ReportsOutputsReplacedBeforeAFailedRename covers a rename
// that fails after an earlier output of the certificate was replaced: changed
// must report it, and the temporary files left must be removed.
func TestReconcile_ReportsOutputsReplacedBeforeAFailedRename(t *testing.T) {
	b := makeBundle(t)
	dir := t.TempDir()
	cert := config.OutputSpec{Format: "pem-cert", Path: filepath.Join(dir, "cert.pem")}
	key := config.OutputSpec{Format: "pem-key", Path: filepath.Join(dir, "key.pem")}
	// The key stages, but no file can be renamed over a directory.
	if err := os.MkdirAll(filepath.Join(key.Path, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}

	changed, err := Reconcile(b, []config.OutputSpec{cert, key})
	if err == nil || !changed {
		t.Fatalf("Reconcile = %v, %v; want an error and a change", changed, err)
	}
	checkContent(t, b, cert)
	checkNoTemps(t, dir)
}

// TestReconcile_UnknownOwnerLeavesTargetUnchanged covers an owner that does
// not resolve. It is looked up for the temporary file, when Unix sets its
// ownership and when Windows creates a key output with read access for the
// owner, so the failure must come before the target is replaced. The output
// is a key because Windows ignores the owner of other formats.
func TestReconcile_UnknownOwnerLeavesTargetUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	spec := config.OutputSpec{Format: "pem-key", Path: path, Owner: "sigil-test-no-such-account"}
	changed, err := Reconcile(makeBundle(t), []config.OutputSpec{spec})
	if err == nil || changed {
		t.Fatalf("Reconcile = %v, %v; want an error and no change", changed, err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "old" {
		t.Fatalf("existing output changed: %q, %v", data, err)
	}
	checkNoTemps(t, dir)
}

// TestReconcile_ReplacesSymlink covers a symbolic link at an output path. It
// is replaced by a regular file even when the file it points to matches, and
// that file is left alone.
func TestReconcile_ReplacesSymlink(t *testing.T) {
	b := makeBundle(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "target.pem")
	if err := os.WriteFile(target, b.CertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	// WriteFile applies the umask; Chmod does not.
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	spec := config.OutputSpec{Format: "pem-cert", Path: filepath.Join(dir, "cert.pem")}
	if err := os.Symlink(target, spec.Path); err != nil {
		t.Skipf("cannot create a symbolic link: %v", err)
	}
	before := fileState(t, target)

	if !mustReconcile(t, b, spec) {
		t.Fatal("the symbolic link was kept")
	}
	if info, err := os.Lstat(spec.Path); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("output is not a regular file: %v, %v", info, err)
	}
	checkContent(t, b, spec)
	checkUntouched(t, target, before)
}

// TestReconcile_KeyOutputsArePrivate writes every format where other users
// may read new files: formats that carry the private key must stay owner-only.
func TestReconcile_KeyOutputsArePrivate(t *testing.T) {
	b := makeBundle(t)
	dir := outputDir(t)
	for _, format := range []string{"pem-cert", "pem-fullchain", "der", "pem-key", "pem-bundle", "pkcs12"} {
		t.Run(format, func(t *testing.T) {
			spec := config.OutputSpec{Format: format, Path: filepath.Join(dir, format), Password: "testpass"}
			if !mustReconcile(t, b, spec) {
				t.Fatal("a missing output reported no change")
			}
			checkMode(t, spec.Path, os.FileMode(outputMode(spec)))
		})
	}
}
