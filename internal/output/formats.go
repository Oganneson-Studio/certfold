package output

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

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

// Reconcile brings the outputs of one certificate, specs, in line with bundle
// and reports whether it rewrote the content of any of them.
//
// The content of an output matches bundle when all of these hold:
//   - os.Lstat finds a regular file at its path. A missing file does not
//     match, and neither does a symbolic link or any other kind of file; a
//     symbolic link is replaced by a regular file, and the file it points to
//     is left alone.
//   - The file holds bundle. A pkcs12 file must decode with
//     pkcs12.DecodeChain(content, spec.Password), and its leaf, the Raw of
//     each chain certificate and its private key (compared with Equal) must
//     be those of bundle. Bytes are not compared: every encoding picks a new
//     random salt and IV, so a byte comparison would rewrite the file, and run
//     the certificate's on_change program, on every reconcile. Any other
//     format must equal encode(bundle, spec) byte for byte. A file that cannot
//     be read or decoded does not match; one rewrite repairs it.
//
// An output whose content matches is not rewritten, but its metadata is
// repaired where it differs:
//   - On Unix, Reconcile chmods the file in place when its permission bits
//     are not outputMode(spec), then chowns it when owner or group is set and
//     its uid or gid is not theirs, in the order stage applies them. If either
//     fails, the error is returned with the output's path before any output
//     is staged; the repairs made before it stay.
//   - On Windows, when owner is set and the file's owner SID is not that of
//     owner, the file is staged again and replaced with the outputs below.
//     Setting the owner in place would leave the DACL as it was, and for a
//     private-key output that DACL grants read access to the owner configured
//     when it was written. The mode is not compared, since Windows does not
//     apply it, and neither is the DACL.
//
// The outputs whose content does not match, and on Windows those staged again
// for their owner, are replaced as one group:
//  1. Stage each of them in order: MkdirAll its directory with 0o755,
//     createTemp, write, Sync, applyMode, applyOwnership on the temporary
//     file, Close. If any step fails, every temporary file of the group is
//     removed and the error returned; no target has been touched. Setting
//     ownership after the rename instead would break this guarantee.
//  2. Commit: rename each temporary file over its target in order. If a
//     rename fails, the temporary files left are removed and the error
//     returned; the targets already replaced stay replaced, and the next
//     reconcile completes the rest.
//
// The errors name the output, never a temporary file, whose random name would
// make a failure that repeats read differently each time.
//
// changed reports whether the content of at least one target was replaced,
// also when err is not nil. Repairing metadata alone does not count, and is
// not checked with another stat, because some filesystems cannot hold
// permission bits: WSL's drvfs and 9p mounts without the metadata option,
// CIFS without Unix extensions, and WSLC bind mounts, which report 0777 for
// every file. chmod succeeds on them without effect, so every reconcile finds
// the mode differing again. Were that a change, it would run the
// certificate's on_change program on every reconcile, with no error to back
// off from; as it is, it costs one chmod call. Private-key outputs on Windows
// are created by securefile.CreateTemp with read access for owner.
func Reconcile(bundle *CertBundle, specs []config.OutputSpec) (changed bool, err error) {
	var stale []config.OutputSpec
	// rewrites[i] reports whether stale[i] is staged for its content, and not
	// only for its owner.
	var rewrites []bool
	for _, spec := range specs {
		info, ok := contentMatches(bundle, spec)
		if ok {
			restage, err := repairMetadata(info, spec)
			if err != nil {
				return false, fmt.Errorf("write %s: %w", spec.Path, err)
			}
			if !restage {
				continue
			}
		}
		stale = append(stale, spec)
		rewrites = append(rewrites, !ok)
	}

	temps := make([]string, 0, len(stale))
	for _, spec := range stale {
		tmp, err := stage(bundle, spec)
		if err != nil {
			for _, name := range temps {
				_ = os.Remove(name)
			}
			return false, fmt.Errorf("write %s: %w", spec.Path, err)
		}
		temps = append(temps, tmp)
	}

	for i, spec := range stale {
		if err := os.Rename(temps[i], spec.Path); err != nil {
			for _, name := range temps[i:] {
				_ = os.Remove(name)
			}
			return changed, fmt.Errorf("replace %s: %w", spec.Path, withoutTempName(err))
		}
		changed = changed || rewrites[i]
	}
	return changed, nil
}

// contentMatches reports whether the output spec describes is a regular file
// that already holds the content Reconcile would write there, and returns
// what os.Lstat found for it.
func contentMatches(bundle *CertBundle, spec config.OutputSpec) (info os.FileInfo, ok bool) {
	info, err := os.Lstat(spec.Path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, false
	}
	data, err := os.ReadFile(spec.Path)
	if err != nil {
		return nil, false
	}
	if spec.Format == "pkcs12" {
		return info, pkcs12Matches(bundle, data, spec.Password)
	}
	want, err := encode(bundle, spec)
	return info, err == nil && bytes.Equal(data, want)
}

// pkcs12Matches reports whether data decodes with password to the private
// key, leaf and chain of bundle.
func pkcs12Matches(bundle *CertBundle, data []byte, password string) bool {
	key, leaf, chain, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return false
	}
	wantKey, wantLeaf, wantChain, err := pkcs12Contents(bundle)
	if err != nil {
		return false
	}
	k, ok := wantKey.(interface{ Equal(crypto.PrivateKey) bool })
	return ok && k.Equal(key) && leaf.Equal(wantLeaf) &&
		slices.EqualFunc(chain, wantChain, (*x509.Certificate).Equal)
}

// stage writes the output spec describes to a new temporary file in its
// directory and returns the file's name, for the caller to rename over
// spec.Path. The file has the output's mode and ownership before it is
// closed: once staged, only the rename is left.
func stage(bundle *CertBundle, spec config.OutputSpec) (string, error) {
	data, err := encode(bundle, spec)
	if err != nil {
		return "", fmt.Errorf("encode %s: %w", spec.Format, err)
	}
	dir := filepath.Dir(spec.Path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir: %w", err)
	}

	// createTemp gives the temp file its access controls before any data is
	// written.
	tmp, err := createTemp(dir, spec)
	if err != nil {
		return "", fmt.Errorf("create temp: %w", withoutTempName(err))
	}
	name := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(name)
	}

	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return "", fmt.Errorf("write temp: %w", withoutTempName(err))
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return "", fmt.Errorf("sync temp: %w", withoutTempName(err))
	}
	if err := applyMode(tmp, spec); err != nil {
		cleanup()
		return "", fmt.Errorf("chmod temp: %w", withoutTempName(err))
	}
	if err := applyOwnership(name, spec.Owner, spec.Group); err != nil {
		cleanup()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return "", fmt.Errorf("close temp: %w", withoutTempName(err))
	}
	return name, nil
}

// withoutTempName returns the cause of err, an error of an operation on a
// temporary file, without the *os.PathError or *os.LinkError around it that
// names the file: the name is random, so a failure that repeats would read
// differently each time, and sigilc logs its last error again whenever the
// text changes. The caller names the output instead. Other errors are
// returned as they are.
func withoutTempName(err error) error {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err
	}
	var linkErr *os.LinkError
	if errors.As(err, &linkErr) {
		return linkErr.Err
	}
	return err
}

func outputMode(spec config.OutputSpec) int {
	if spec.Mode != 0 {
		return int(spec.Mode)
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
	privKey, leaf, chain, err := pkcs12Contents(bundle)
	if err != nil {
		return nil, err
	}
	return pkcs12.Modern.Encode(privKey, leaf, chain, password)
}

// pkcs12Contents parses what a pkcs12 output of bundle holds, in the order
// pkcs12.DecodeChain returns it. Encoding and comparing both use it, so they
// cannot disagree on the contents.
func pkcs12Contents(bundle *CertBundle) (privKey interface{}, leaf *x509.Certificate, chain []*x509.Certificate, err error) {
	leaf, err = parseCert(bundle.CertPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse leaf cert: %w", err)
	}
	privKey, err = parseKey(bundle.KeyPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse private key: %w", err)
	}
	chain, err = parseChain(bundle.ChainPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse chain: %w", err)
	}
	return privKey, leaf, chain, nil
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
