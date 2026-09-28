package output

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/Oganneson-Studio/sigil/internal/config"
)

// CertBundle contains the raw materials needed to produce any output format.
// All PEM fields are expected to contain one or more PEM-encoded blocks.
type CertBundle struct {
	// CertPEM is the end-entity certificate (one PEM block).
	CertPEM []byte
	// ChainPEM contains intermediate certificates in PEM form (may be empty).
	ChainPEM []byte
	// KeyPEM is the private key (one PEM block, any supported key type).
	KeyPEM []byte
}

// Write converts bundle to the format described by spec and atomically writes
// it to spec.Path, applying mode/owner/group if set.
func Write(bundle *CertBundle, spec config.OutputSpec) error {
	data, err := encode(bundle, spec)
	if err != nil {
		return fmt.Errorf("encode %s: %w", spec.Format, err)
	}
	if err := atomicWrite(spec, data); err != nil {
		return fmt.Errorf("write %s: %w", spec.Path, err)
	}
	return applyOwnership(spec.Path, spec.Owner, spec.Group)
}

// Reconcile brings the outputs of one certificate, specs, in line with bundle
// and reports whether it replaced any of them.
//
// An output matches bundle when all of these hold:
//   - os.Lstat finds a regular file at its path. A missing file does not
//     match, and neither does a symbolic link or any other kind of file; a
//     symbolic link is replaced by a regular file, as Write replaces it.
//   - Its content matches. A pkcs12 file must decode with
//     pkcs12.DecodeChain(content, spec.Password), and its leaf, the Raw of
//     each chain certificate and its private key (compared with Equal) must
//     be those of bundle. Bytes are not compared: every encoding picks a new
//     random salt and IV, so a byte comparison would rewrite the file, and run
//     the certificate's on_change program, on every reconcile. Any other
//     format must equal encode(bundle, spec) byte for byte. A file that cannot
//     be read or decoded does not match; one rewrite repairs it.
//   - On Unix, its permission bits equal outputMode(spec), and its uid and
//     gid are those of owner and group when they are set.
//   - On Windows, its owner SID is that of owner when owner is set. The mode
//     is not compared, since Windows does not apply it, and neither is the
//     DACL.
//
// The outputs that do not match are replaced as one group:
//  1. Stage each of them in order: MkdirAll its directory with 0o755,
//     createTemp, write, Sync, applyMode, applyOwnership on the temporary
//     file, Close. If any step fails, every temporary file of the group is
//     removed and the error returned; no target has been touched. Write sets
//     ownership after the rename instead, which would break this guarantee.
//  2. Commit: rename each temporary file over its target in order. If a
//     rename fails, the temporary files left are removed and the error
//     returned; the targets already replaced count as changed, and the next
//     reconcile completes the rest.
//
// changed reports whether at least one target was replaced, also when err is
// not nil. Private-key outputs on Windows keep being created by
// securefile.CreateTemp with read access for owner, as Write creates them.
//
// This is a stub: it rewrites every output with Write, and reports changed
// once one has been written.
func Reconcile(bundle *CertBundle, specs []config.OutputSpec) (changed bool, err error) {
	for _, spec := range specs {
		if err = Write(bundle, spec); err != nil {
			return changed, err
		}
		changed = true
	}
	return changed, nil
}

func outputMode(spec config.OutputSpec) int {
	if spec.Mode != 0 {
		return spec.Mode
	}
	if carriesKey(spec.Format) {
		return 0o600
	}
	return 0o644
}

// carriesKey reports whether an output format contains the private key.
func carriesKey(format string) bool {
	switch format {
	case "pem-key", "pem-bundle", "pkcs12":
		return true
	default:
		return false
	}
}

// encode serialises bundle into the wire bytes for spec.Format.
func encode(bundle *CertBundle, spec config.OutputSpec) ([]byte, error) {
	switch spec.Format {
	case "pem-cert":
		return bundle.CertPEM, nil

	case "pem-key":
		return bundle.KeyPEM, nil

	case "pem-fullchain":
		return append(bundle.CertPEM, bundle.ChainPEM...), nil

	case "pem-bundle":
		// cert + chain + key concatenated
		out := make([]byte, 0, len(bundle.CertPEM)+len(bundle.ChainPEM)+len(bundle.KeyPEM))
		out = append(out, bundle.CertPEM...)
		out = append(out, bundle.ChainPEM...)
		out = append(out, bundle.KeyPEM...)
		return out, nil

	case "der":
		cert, err := parseCert(bundle.CertPEM)
		if err != nil {
			return nil, err
		}
		return cert.Raw, nil

	case "pkcs12":
		return encodePKCS12(bundle, spec.Password)

	default:
		return nil, fmt.Errorf("unknown format %q", spec.Format)
	}
}

func encodePKCS12(bundle *CertBundle, password string) ([]byte, error) {
	leaf, err := parseCert(bundle.CertPEM)
	if err != nil {
		return nil, fmt.Errorf("parse leaf cert: %w", err)
	}
	privKey, err := parseKey(bundle.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	chain, err := parseChain(bundle.ChainPEM)
	if err != nil {
		return nil, fmt.Errorf("parse chain: %w", err)
	}
	return pkcs12.Modern.Encode(privKey, leaf, chain, password)
}

// atomicWrite writes data to spec.Path using a temp-file + rename so callers
// always see a complete file. createTemp gives the temp file its access
// controls before any data is written.
func atomicWrite(spec config.OutputSpec, data []byte) error {
	dir := filepath.Dir(spec.Path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	// Write to a sibling temp file so rename stays on the same filesystem.
	tmp, err := createTemp(dir, spec)
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("write temp: %w", err)
	}
	if err := applyMode(tmp, spec); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, spec.Path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// parseCert decodes the first PEM certificate block.
func parseCert(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM data")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected CERTIFICATE block, got %q", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

// parseChain decodes all PEM certificate blocks from data (chain may be empty).
func parseChain(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemData
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse chain cert: %w", err)
		}
		certs = append(certs, c)
	}
	return certs, nil
}

// parseKey decodes the first PEM private key block (PKCS8, EC, or RSA).
func parseKey(pemData []byte) (interface{}, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM data")
	}
	switch block.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported key type %q", block.Type)
	}
}
