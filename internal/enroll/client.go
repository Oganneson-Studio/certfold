package enroll

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/securefile"
	"github.com/Oganneson-Studio/sigil/pkg/proto"
)

// KeyAndCSR holds the generated private key (PEM) and CSR (DER bytes).
type KeyAndCSR struct {
	KeyPEM []byte
	CSRDER []byte
}

// GenerateKeyAndCSR creates an ECDSA P-256 key pair and a CSR with CN=name.
func GenerateKeyAndCSR(name string) (*KeyAndCSR, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: name}}, priv)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return &KeyAndCSR{KeyPEM: keyPEM, CSRDER: csrDER}, nil
}

// SystemCertPool loads the operating system trust store. It is a variable only
// so tests can stand in for a publicly trusted CA.
var SystemCertPool = x509.SystemCertPool

// ServerRoots returns the roots that authenticate the sigils HTTPS endpoint:
// the operating system trust store, for a publicly trusted
// server.tls_cert_file, plus the sigil mini-CA in caCertPEM, which signs the
// default server certificate. Enrollment and every later request use it.
func ServerRoots(caCertPEM string) (*x509.CertPool, error) {
	roots, err := SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM([]byte(caCertPEM)) {
		return nil, fmt.Errorf("parse server CA certificate")
	}
	return roots, nil
}

// PostEnroll sends the enroll request for tokenStr, which DecodeToken read as
// token, to the server the token names, and returns the client certificate,
// in PEM, that the server issued for csrDER, the raw CSR.
//
// The token carries the expected server CA certificate. TLS is verified against
// that pinned CA and the system roots before the bearer token or CSR is sent.
// The client certificate is checked as sigilc checks a renewed identity: it
// must be for the token's client name, chain to the token's CA for client
// authentication, and hold the key of the CSR. The identity to save is the
// token's CA and this certificate.
func PostEnroll(token *Token, tokenStr string, csrDER []byte) (string, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return "", fmt.Errorf("parse CSR: %w", err)
	}
	roots, err := ServerRoots(token.CACert)
	if err != nil {
		return "", fmt.Errorf("token does not contain a valid server CA certificate")
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	reqBody, err := json.Marshal(proto.EnrollRequest{Token: tokenStr, CSR: string(csrPEM)})
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	enrollClient := &http.Client{
		Timeout: 30 * time.Second,
		// The request carries the token, so it goes to the server whose TLS
		// was checked and nowhere else: a 307 or 308 would send it again, to
		// any host and over plain HTTP too.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    roots,
				MinVersion: tls.VersionTLS13,
			},
		},
	}
	resp, err := enrollClient.Post(token.ServerURL+"/v1/enroll", "application/json", bytes.NewReader(reqBody)) //nolint:noctx
	if err != nil {
		return "", fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// The server says why, such as that the token was already used. The
		// text comes from the network: sigilc makes the error one line.
		reason, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
		return "", fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(reason)))
	}
	var out proto.EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	return checkIssued(token, out.ClientCert, csr)
}

// checkIssued checks the client certificate certPEM that the server issued at
// enrollment, and returns it re-encoded, so that what sigilc saves is what
// was checked. Its errors quote the network.
func checkIssued(token *Token, certPEM string, csr *x509.CertificateRequest) (string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("response does not contain a client certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse client certificate: %w", err)
	}
	if leaf.Subject.CommonName != token.Name {
		return "", fmt.Errorf("client certificate name %q does not match client %q", leaf.Subject.CommonName, token.Name)
	}
	// Only the token's CA: the one in the system roots that may have signed
	// the server's TLS certificate does not sign clients.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(token.CACert)) {
		return "", fmt.Errorf("token does not contain a valid server CA certificate")
	}
	// Checked at its own NotBefore, not by this host's clock: by the time the
	// answer arrives the server has used up the token, so a clock behind the
	// server's by more than the minute the mini-CA backdates would otherwise
	// fail an enrollment that cannot be retried. The validity says nothing
	// here: the certificate must hold the key made for this request, so it
	// cannot be an old one replayed.
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: leaf.NotBefore,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return "", fmt.Errorf("verify client certificate: %w", err)
	}
	if key, ok := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool }); !ok || !key.Equal(csr.PublicKey) {
		return "", fmt.Errorf("client certificate is not for the key of the request")
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})), nil
}

// SaveIdentity writes the identity into the client.yaml at cfgPath, at
// enrollment and at every identity renewal. It edits the YAML tree, as
// config.AddCertificateSpec does server.yaml: the value of the identity key
// is replaced, or the key appended, and the rest keeps the operator's
// comments, key order and text. Decoding into a map instead would rewrite
// scalars as YAML reads them, such as a PKCS#12 password 0123 as 83.
func SaveIdentity(cfgPath string, caCert, clientCert, clientKey string) error {
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("parse yaml: %w", err)
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("client config root must be a mapping")
	}
	var identity yaml.Node
	if err := identity.Encode(config.IdentitySection{
		CACert:     caCert,
		ClientCert: clientCert,
		ClientKey:  clientKey,
	}); err != nil {
		return fmt.Errorf("encode identity: %w", err)
	}

	root := doc.Content[0]
	i := 0
	for i < len(root.Content) && root.Content[i].Value != "identity" {
		i += 2
	}
	if i < len(root.Content) {
		root.Content[i+1] = &identity
	} else {
		key := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "identity"}
		root.Content = append(root.Content, key, &identity)
	}

	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return fmt.Errorf("marshal yaml: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("marshal yaml: %w", err)
	}
	return securefile.WriteFile(cfgPath, out.Bytes())
}
