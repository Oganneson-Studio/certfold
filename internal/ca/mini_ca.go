package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/securefile"
)

const (
	caSubDir      = "ca"
	caCertFile    = "ca.crt"
	caKeyFile     = "ca.key"
	caSerialFile  = "serial"
	caValidYears  = 10
	leafValidDays = 90
)

// MiniCA is the Sigil internal certificate authority used for mTLS client
// certificate issuance. All public methods are goroutine-safe.
type MiniCA struct {
	cert       *x509.Certificate
	key        *ecdsa.PrivateKey
	serial     atomic.Int64
	serialMu   sync.Mutex
	serialPath string
}

// Bootstrap ensures a CA certificate and key exist under dataDir/ca/.
// If they do not exist, a new root CA is generated and written to disk.
// Returns the loaded or newly created *MiniCA.
func Bootstrap(dataDir string) (*MiniCA, error) {
	dir := filepath.Join(dataDir, caSubDir)
	if err := securefile.EnsurePrivateDirectory(dir); err != nil {
		return nil, fmt.Errorf("protect ca dir: %w", err)
	}
	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)
	serialPath := filepath.Join(dir, caSerialFile)

	if fileExists(certPath) && fileExists(keyPath) {
		return Load(certPath, keyPath)
	}

	cert, key, err := generateRootCA()
	if err != nil {
		return nil, fmt.Errorf("generate root CA: %w", err)
	}
	if err := writeCertPEM(certPath, cert); err != nil {
		return nil, fmt.Errorf("write ca.crt: %w", err)
	}
	if err := writeKeyPEM(keyPath, key); err != nil {
		return nil, fmt.Errorf("write ca.key: %w", err)
	}
	parsed, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, err
	}
	initialSerial := parsed.SerialNumber.Int64()
	if err := persistSerial(serialPath, initialSerial); err != nil {
		return nil, fmt.Errorf("initialize CA serial: %w", err)
	}
	m := &MiniCA{cert: parsed, key: key, serialPath: serialPath}
	m.serial.Store(initialSerial)
	return m, nil
}

// Load reads ca.crt and ca.key from disk and returns a *MiniCA.
func Load(certPath, keyPath string) (*MiniCA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", certPath, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", keyPath, err)
	}
	m, err := ParsePEM(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	serialPath := filepath.Join(filepath.Dir(keyPath), caSerialFile)
	serial, err := loadSerial(serialPath, m.cert.SerialNumber.Int64())
	if err != nil {
		return nil, fmt.Errorf("load CA serial: %w", err)
	}
	m.serialPath = serialPath
	m.serial.Store(serial)
	return m, nil
}

// ParsePEM constructs a MiniCA from PEM-encoded cert and key bytes.
// Useful for tests that do not touch the filesystem.
func ParsePEM(certPEM, keyPEM []byte) (*MiniCA, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca cert: %w", err)
	}

	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, fmt.Errorf("no private key PEM block")
	}
	key, err := parsePrivateKey(kb)
	if err != nil {
		return nil, fmt.Errorf("parse ca key: %w", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("CA key must be ECDSA")
	}
	m := &MiniCA{cert: cert, key: ecKey}
	m.serial.Store(cert.SerialNumber.Int64())
	return m, nil
}

// Cert returns the parsed CA certificate.
func (m *MiniCA) Cert() *x509.Certificate { return m.cert }

// CertPEM returns the CA certificate in PEM format.
func (m *MiniCA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.cert.Raw})
}

// Sign issues a client certificate for the given CSR. Only the CSR's public
// key is used: the subject is CN=name and no subject alternative names are
// copied, so a client cannot choose the identities its certificate names.
// Validity is leafValidDays from now.
func (m *MiniCA) Sign(csr *x509.CertificateRequest, name string) ([]byte, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature: %w", err)
	}
	serial, err := m.nextSerial()
	if err != nil {
		return nil, fmt.Errorf("allocate serial: %w", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(leafValidDays * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, m.cert, csr.PublicKey, m.key)
	if err != nil {
		return nil, fmt.Errorf("sign cert: %w", err)
	}
	return der, nil
}

// IssueServerCert signs a TLS server certificate valid for the given hosts
// (DNS names and/or IP addresses). Returns the cert and key as PEM bytes.
// KeyUsage is DigitalSignature + KeyEncipherment; ExtKeyUsage is ServerAuth.
// Validity is 1 year from now.
func (m *MiniCA) IssueServerCert(hosts []string) (certPEM, keyPEM []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	serial, err := m.nextSerial()
	if err != nil {
		return nil, nil, fmt.Errorf("allocate serial: %w", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "sigils"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, m.cert, &priv.PublicKey, m.key)
	if err != nil {
		return nil, nil, fmt.Errorf("sign server cert: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// Fingerprint returns the hex-encoded SHA-256 fingerprint of a DER-encoded
// certificate, formatted as "sha256:AABB...".
func Fingerprint(certDER []byte) string {
	sum := sha256.Sum256(certDER)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// nextSerial reserves and persists a serial before it can be used. Persisting
// first means a crash may skip a serial, but it cannot cause that serial to be
// issued again after restart.
func (m *MiniCA) nextSerial() (int64, error) {
	m.serialMu.Lock()
	defer m.serialMu.Unlock()

	current := m.serial.Load()
	if current == math.MaxInt64 {
		return 0, fmt.Errorf("serial space exhausted")
	}
	next := current + 1
	if m.serialPath != "" {
		if err := persistSerial(m.serialPath, next); err != nil {
			return 0, err
		}
	}
	m.serial.Store(next)
	return next, nil
}

func loadSerial(path string, minimum int64) (int64, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		serial, parseErr := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
		if parseErr != nil || serial < minimum {
			return 0, fmt.Errorf("invalid serial state in %s", path)
		}
		return serial, nil
	}
	if !os.IsNotExist(err) {
		return 0, err
	}

	// Existing installations have no serial state. Their old in-memory serials
	// were small counters, so a time-based floor avoids reusing those values.
	serial := time.Now().UnixNano()
	if serial < minimum {
		serial = minimum
	}
	if err := persistSerial(path, serial); err != nil {
		return 0, err
	}
	return serial, nil
}

func persistSerial(path string, serial int64) error {
	return securefile.WriteFile(path, []byte(strconv.FormatInt(serial, 10)+"\n"))
}

// generateRootCA creates a new self-signed ECDSA P-256 root CA.
func generateRootCA() (certDER []byte, key *ecdsa.PrivateKey, err error) {
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Sigil Root CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(caValidYears * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certDER, err = x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	return certDER, key, err
}

func writeCertPEM(path string, der []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func writeKeyPEM(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if keyPEM == nil {
		return fmt.Errorf("encode private key PEM")
	}
	return securefile.WriteFile(path, keyPEM)
}

func parsePrivateKey(block *pem.Block) (any, error) {
	switch block.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type %q", block.Type)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
