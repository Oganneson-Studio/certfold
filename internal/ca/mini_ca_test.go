package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// makeCSR creates a test CSR with the given CN signed by a fresh ECDSA key.
func makeCSR(t *testing.T, cn string) *x509.CertificateRequest {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tpl, priv)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	return csr
}

// bootstrapInTemp runs Bootstrap in a t.TempDir() and returns the MiniCA.
func bootstrapInTemp(t *testing.T) *MiniCA {
	t.Helper()
	dir := t.TempDir()
	m, err := Bootstrap(dir)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	return m
}

// keyToPEM encodes an ECDSA private key as PKCS8 PEM.
func keyToPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ---------------------------------------------------------------------------
// Bootstrap & persistence round-trip
// ---------------------------------------------------------------------------

func TestBootstrap_CreatesFiles(t *testing.T) {
	dir := t.TempDir()
	m, err := Bootstrap(dir)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if m == nil {
		t.Fatal("Bootstrap returned nil")
	}

	// Second call must load the same CA (same serial).
	m2, err := Bootstrap(dir)
	if err != nil {
		t.Fatalf("second Bootstrap: %v", err)
	}
	if m.cert.SerialNumber.Cmp(m2.cert.SerialNumber) != 0 {
		t.Errorf("serial mismatch: %v vs %v", m.cert.SerialNumber, m2.cert.SerialNumber)
	}
}

// TestBootstrapRefusesHalfPresentCA covers a data directory that holds only
// one of ca.crt and ca.key, such as one restored from a backup that left out
// private keys. A new root would silently replace the one every enrolled
// client trusts, and overwrite the file that is left. Bootstrap must fail
// instead, name both files, and leave the one that is left alone.
func TestBootstrapRefusesHalfPresentCA(t *testing.T) {
	for _, missing := range []string{caKeyFile, caCertFile} {
		t.Run("without "+missing, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := Bootstrap(dir); err != nil {
				t.Fatal(err)
			}
			kept := caCertFile
			if missing == caCertFile {
				kept = caKeyFile
			}
			keptPath := filepath.Join(dir, caSubDir, kept)
			missingPath := filepath.Join(dir, caSubDir, missing)
			before, err := os.ReadFile(keptPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(missingPath); err != nil {
				t.Fatal(err)
			}

			_, err = Bootstrap(dir)
			if err == nil {
				t.Errorf("Bootstrap without %s succeeded, want an error", missing)
			} else if !strings.Contains(err.Error(), keptPath) || !strings.Contains(err.Error(), missingPath) {
				t.Errorf("Bootstrap without %s: error %q does not name %s and %s", missing, err, keptPath, missingPath)
			}
			after, err := os.ReadFile(keptPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Errorf("Bootstrap without %s rewrote %s", missing, kept)
			}
		})
	}
}

func TestBootstrap_ProtectsCAStorage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes are not available on Windows; securefile DACL behavior is tested separately")
	}
	dataDir := t.TempDir()
	caDir := filepath.Join(dataDir, caSubDir)
	if err := os.Mkdir(caDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Bootstrap(dataDir); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	dirInfo, err := os.Stat(caDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("CA directory mode = %#o, want 0700", got)
	}
	keyInfo, err := os.Stat(filepath.Join(caDir, caKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if got := keyInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("CA key mode = %#o, want 0600", got)
	}
}

func TestBootstrap_RootCAProperties(t *testing.T) {
	m := bootstrapInTemp(t)

	if m.cert.Subject.CommonName != "Certfold Root CA" {
		t.Errorf("CN: got %q", m.cert.Subject.CommonName)
	}
	if !m.cert.IsCA {
		t.Error("IsCA should be true")
	}
	if m.cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("KeyUsageCertSign not set")
	}
	validity := m.cert.NotAfter.Sub(m.cert.NotBefore)
	minExpected := time.Duration(caValidYears-1) * 365 * 24 * time.Hour
	if validity < minExpected {
		t.Errorf("validity %v shorter than expected %v", validity, minExpected)
	}
}

// ---------------------------------------------------------------------------
// ParsePEM round-trip
// ---------------------------------------------------------------------------

func TestParsePEM_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	orig, err := Bootstrap(dir)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	certPEM := orig.CertPEM()
	keyPEMBytes, err := keyToPEM(orig.key)
	if err != nil {
		t.Fatalf("keyToPEM: %v", err)
	}

	loaded, err := ParsePEM(certPEM, keyPEMBytes)
	if err != nil {
		t.Fatalf("ParsePEM: %v", err)
	}
	if loaded.cert.SerialNumber.Cmp(orig.cert.SerialNumber) != 0 {
		t.Error("serial mismatch after ParsePEM round-trip")
	}
}

// ---------------------------------------------------------------------------
// Sign
// ---------------------------------------------------------------------------

func TestSign_ValidCert(t *testing.T) {
	m := bootstrapInTemp(t)
	csr := makeCSR(t, "web-1")

	der, err := m.Sign(csr, "web-1")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	if cert.Subject.CommonName != "web-1" {
		t.Errorf("CN: got %q", cert.Subject.CommonName)
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("DigitalSignature not set")
	}

	hasClientAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}
	if !hasClientAuth {
		t.Error("ExtKeyUsageClientAuth not present")
	}

	// Verify expiry is ~90 days from now
	validity := time.Until(cert.NotAfter)
	if validity < 89*24*time.Hour || validity > 91*24*time.Hour {
		t.Errorf("validity %v not near 90d", validity)
	}
}

func TestSign_VerifiableByCA(t *testing.T) {
	m := bootstrapInTemp(t)
	csr := makeCSR(t, "srv-2")

	der, err := m.Sign(csr, "srv-2")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(m.cert)
	opts := x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := cert.Verify(opts); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestSign_IgnoresCSRSubjectAltNames(t *testing.T) {
	m := bootstrapInTemp(t)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse("spiffe://example.com/workload")
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: "requested-name"},
		DNSNames:       []string{"certfolds", "api.example.com"},
		IPAddresses:    []net.IP{net.ParseIP("127.0.0.1")},
		EmailAddresses: []string{"ops@example.com"},
		URIs:           []*url.URL{uri},
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}

	certDER, err := m.Sign(csr, "web-1")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "web-1" {
		t.Errorf("CN = %q, want web-1", cert.Subject.CommonName)
	}
	if len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 || len(cert.EmailAddresses) != 0 || len(cert.URIs) != 0 {
		t.Fatalf("client certificate carries CSR SANs: dns=%v ip=%v email=%v uri=%v",
			cert.DNSNames, cert.IPAddresses, cert.EmailAddresses, cert.URIs)
	}
}

func TestSign_InvalidCSRSignature(t *testing.T) {
	m := bootstrapInTemp(t)

	// Build a valid CSR then mutate its TBS bytes to invalidate the signature.
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "bad"}}
	der, _ := x509.CreateCertificateRequest(rand.Reader, tpl, priv)
	csr, _ := x509.ParseCertificateRequest(der)

	// Corrupt the TBS so CheckSignature fails.
	csr.RawTBSCertificateRequest = append(csr.RawTBSCertificateRequest, 0xFF, 0xFE)

	_, err := m.Sign(csr, "bad")
	if err == nil {
		t.Fatal("expected error for tampered CSR, got nil")
	}
}

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------

func TestFingerprint(t *testing.T) {
	m := bootstrapInTemp(t)
	fp := Fingerprint(m.cert.Raw)

	if !strings.HasPrefix(fp, "sha256:") {
		t.Errorf("fingerprint prefix: got %q", fp)
	}
	// sha256 hex is 64 chars; total = 7 ("sha256:") + 64 = 71
	if len(fp) != 71 {
		t.Errorf("fingerprint length: got %d", len(fp))
	}

	// Same input → same result
	fp2 := Fingerprint(m.cert.Raw)
	if fp != fp2 {
		t.Error("Fingerprint not deterministic")
	}
}

// ---------------------------------------------------------------------------
// Serial monotonically increases across Sign calls
// ---------------------------------------------------------------------------

func TestSign_SerialIncrement(t *testing.T) {
	m := bootstrapInTemp(t)

	derA, _ := m.Sign(makeCSR(t, "a"), "a")
	derB, _ := m.Sign(makeCSR(t, "b"), "b")

	certA, _ := x509.ParseCertificate(derA)
	certB, _ := x509.ParseCertificate(derB)

	if certB.SerialNumber.Cmp(certA.SerialNumber) <= 0 {
		t.Errorf("serial did not increment: %v <= %v", certB.SerialNumber, certA.SerialNumber)
	}
}

func TestSign_SerialPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	m, err := Bootstrap(dir)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	clientDER, err := m.Sign(makeCSR(t, "client"), "client")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	clientCert, err := x509.ParseCertificate(clientDER)
	if err != nil {
		t.Fatalf("parse client cert: %v", err)
	}

	reloaded, err := Bootstrap(dir)
	if err != nil {
		t.Fatalf("Bootstrap after restart: %v", err)
	}
	serverPEM, _, err := reloaded.IssueServerCert([]string{"localhost"})
	if err != nil {
		t.Fatalf("IssueServerCert: %v", err)
	}
	block, _ := pem.Decode(serverPEM)
	if block == nil {
		t.Fatal("no certificate PEM block")
	}
	serverCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}
	if serverCert.SerialNumber.Cmp(clientCert.SerialNumber) <= 0 {
		t.Fatalf("serial after restart = %v, want greater than %v", serverCert.SerialNumber, clientCert.SerialNumber)
	}

	state, err := os.ReadFile(filepath.Join(dir, caSubDir, caSerialFile))
	if err != nil {
		t.Fatalf("read serial state: %v", err)
	}
	if got := strings.TrimSpace(string(state)); got != serverCert.SerialNumber.String() {
		t.Fatalf("serial state = %q, want %s", got, serverCert.SerialNumber)
	}
}

func TestBootstrap_LegacyCAStartsAboveOldSerials(t *testing.T) {
	dir := t.TempDir()
	m, err := Bootstrap(dir)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	oldDER, err := m.Sign(makeCSR(t, "old"), "old")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	oldCert, err := x509.ParseCertificate(oldDER)
	if err != nil {
		t.Fatalf("parse old cert: %v", err)
	}
	serialPath := filepath.Join(dir, caSubDir, caSerialFile)
	if err := os.Remove(serialPath); err != nil {
		t.Fatalf("remove serial state: %v", err)
	}

	reloaded, err := Bootstrap(dir)
	if err != nil {
		t.Fatalf("Bootstrap legacy CA: %v", err)
	}
	newDER, err := reloaded.Sign(makeCSR(t, "new"), "new")
	if err != nil {
		t.Fatalf("Sign after migration: %v", err)
	}
	newCert, err := x509.ParseCertificate(newDER)
	if err != nil {
		t.Fatalf("parse new cert: %v", err)
	}
	if newCert.SerialNumber.Cmp(oldCert.SerialNumber) <= 0 {
		t.Fatalf("migrated serial = %v, want greater than old serial %v", newCert.SerialNumber, oldCert.SerialNumber)
	}
}

func TestBootstrap_RejectsCorruptSerialState(t *testing.T) {
	dir := t.TempDir()
	if _, err := Bootstrap(dir); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	serialPath := filepath.Join(dir, caSubDir, caSerialFile)
	if err := os.WriteFile(serialPath, []byte("not-a-serial\n"), 0o600); err != nil {
		t.Fatalf("corrupt serial state: %v", err)
	}
	if _, err := Bootstrap(dir); err == nil {
		t.Fatal("expected corrupt serial state to be rejected")
	}
}

func TestSign_ConcurrentSerialsPersistLatest(t *testing.T) {
	const count = 16

	dir := t.TempDir()
	m, err := Bootstrap(dir)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	csrs := make([]*x509.CertificateRequest, count)
	for i := range csrs {
		csrs[i] = makeCSR(t, "concurrent")
	}

	serials := make(chan string, count)
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for _, csr := range csrs {
		wg.Add(1)
		go func(csr *x509.CertificateRequest) {
			defer wg.Done()
			der, err := m.Sign(csr, "concurrent")
			if err != nil {
				errs <- err
				return
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				errs <- err
				return
			}
			serials <- cert.SerialNumber.String()
		}(csr)
	}
	wg.Wait()
	close(errs)
	close(serials)
	for err := range errs {
		t.Fatalf("concurrent Sign: %v", err)
	}

	seen := make(map[string]struct{}, count)
	var maxSerial *big.Int
	for serial := range serials {
		if _, exists := seen[serial]; exists {
			t.Fatalf("duplicate serial %s", serial)
		}
		seen[serial] = struct{}{}
		value, ok := new(big.Int).SetString(serial, 10)
		if !ok {
			t.Fatalf("invalid serial %q", serial)
		}
		if maxSerial == nil || value.Cmp(maxSerial) > 0 {
			maxSerial = value
		}
	}
	if len(seen) != count {
		t.Fatalf("issued %d unique serials, want %d", len(seen), count)
	}

	reloaded, err := Bootstrap(dir)
	if err != nil {
		t.Fatalf("Bootstrap after concurrent signing: %v", err)
	}
	der, err := reloaded.Sign(makeCSR(t, "after-restart"), "after-restart")
	if err != nil {
		t.Fatalf("Sign after restart: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert after restart: %v", err)
	}
	if cert.SerialNumber.Cmp(maxSerial) <= 0 {
		t.Fatalf("serial after restart = %v, want greater than %v", cert.SerialNumber, maxSerial)
	}
}

// ---------------------------------------------------------------------------
// IssueServerCert
// ---------------------------------------------------------------------------

func TestIssueServerCert_SAN(t *testing.T) {
	m := bootstrapInTemp(t)
	certPEM, _, err := m.IssueServerCert([]string{"localhost", "certfold.example.com", "192.168.1.1"})
	if err != nil {
		t.Fatalf("IssueServerCert: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM block in certPEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	hasDNS := func(name string) bool {
		for _, d := range cert.DNSNames {
			if d == name {
				return true
			}
		}
		return false
	}
	hasIP := func(ip string) bool {
		for _, a := range cert.IPAddresses {
			if a.String() == ip {
				return true
			}
		}
		return false
	}

	if !hasDNS("localhost") {
		t.Error("SAN missing DNS:localhost")
	}
	if !hasDNS("certfold.example.com") {
		t.Error("SAN missing DNS:certfold.example.com")
	}
	if !hasIP("192.168.1.1") {
		t.Error("SAN missing IP:192.168.1.1")
	}
}

func TestIssueServerCert_ServerAuth(t *testing.T) {
	m := bootstrapInTemp(t)
	certPEM, _, err := m.IssueServerCert([]string{"localhost"})
	if err != nil {
		t.Fatalf("IssueServerCert: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	hasServerAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
	}
	if !hasServerAuth {
		t.Error("ExtKeyUsageServerAuth not present")
	}
	// Must NOT have client auth
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			t.Error("unexpected ExtKeyUsageClientAuth on server cert")
		}
	}
}

func TestIssueServerCert_VerifiableByCA(t *testing.T) {
	m := bootstrapInTemp(t)
	certPEM, _, err := m.IssueServerCert([]string{"localhost"})
	if err != nil {
		t.Fatalf("IssueServerCert: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(m.cert)
	opts := x509.VerifyOptions{
		Roots:     pool,
		DNSName:   "localhost",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if _, err := cert.Verify(opts); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

// TestIssuedCertificatesCannotSign pins what keeps a certificate of the
// mini-CA from acting as anything but its own role: neither a client nor the
// server certificate is a CA or may sign certificates, a client certificate
// is for client authentication only, and the server certificate for server
// authentication only. A client certificate that could sign, or authenticate
// a server, would let any enrolled client stand in for certfolds.
func TestIssuedCertificatesCannotSign(t *testing.T) {
	m := bootstrapInTemp(t)
	clientDER, err := m.Sign(makeCSR(t, "web-1"), "web-1")
	if err != nil {
		t.Fatal(err)
	}
	client, err := x509.ParseCertificate(clientDER)
	if err != nil {
		t.Fatal(err)
	}
	serverPEM, _, err := m.IssueServerCert([]string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(serverPEM)
	if block == nil {
		t.Fatal("no server certificate PEM block")
	}
	server, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name string
		cert *x509.Certificate
		eku  x509.ExtKeyUsage
	}{
		{name: "client", cert: client, eku: x509.ExtKeyUsageClientAuth},
		{name: "server", cert: server, eku: x509.ExtKeyUsageServerAuth},
	} {
		if tt.cert.IsCA || tt.cert.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
			t.Errorf("%s certificate can sign: IsCA %v, KeyUsage %d", tt.name, tt.cert.IsCA, tt.cert.KeyUsage)
		}
		if !slices.Equal(tt.cert.ExtKeyUsage, []x509.ExtKeyUsage{tt.eku}) || len(tt.cert.UnknownExtKeyUsage) != 0 {
			t.Errorf("%s certificate ExtKeyUsage = %v (unknown %v), want only %v",
				tt.name, tt.cert.ExtKeyUsage, tt.cert.UnknownExtKeyUsage, tt.eku)
		}
	}
}
