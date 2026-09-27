package enroll

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"gopkg.in/yaml.v3"

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

// PostEnroll sends the enroll request to the server and returns the response.
// tokenStr is the opaque base64url token from Create. csrDER is the raw CSR.
//
// The token carries the expected server CA certificate. TLS is verified against
// that pinned CA before the bearer token or CSR is sent.
func PostEnroll(serverURL, tokenStr string, csrDER []byte) (*proto.EnrollResponse, error) {
	payload, err := decodeToken(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("decode token: %w", err)
	}
	if payload.ServerURL != serverURL {
		return nil, fmt.Errorf("token server URL %q does not match %q", payload.ServerURL, serverURL)
	}
	u, err := url.ParseRequestURI(serverURL)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("invalid server URL %q", serverURL)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM([]byte(payload.CACert)) {
		return nil, fmt.Errorf("token does not contain a valid server CA certificate")
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	reqBody, err := json.Marshal(proto.EnrollRequest{Token: tokenStr, CSR: string(csrPEM)})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	enrollClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    roots,
				MinVersion: tls.VersionTLS13,
			},
		},
	}
	resp, err := enrollClient.Post(serverURL+"/v1/enroll", "application/json", bytes.NewReader(reqBody)) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d", resp.StatusCode)
	}
	var out proto.EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &out, nil
}

// identityPatch is the subset of client.yaml we update after enroll.
type identityPatch struct {
	Identity struct {
		CACert     string `yaml:"ca_cert"`
		ClientCert string `yaml:"client_cert"`
		ClientKey  string `yaml:"client_key"`
	} `yaml:"identity"`
}

// SaveIdentity writes the identity fields into the YAML file at cfgPath,
// preserving all other content by unmarshaling and re-marshaling the document.
func SaveIdentity(cfgPath string, caCert, clientCert, clientKey string) error {
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	// Parse into generic map to preserve unknown fields.
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("parse yaml: %w", err)
	}
	if doc == nil {
		doc = make(map[string]any)
	}
	doc["identity"] = map[string]any{
		"ca_cert":     caCert,
		"client_cert": clientCert,
		"client_key":  clientKey,
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshal yaml: %w", err)
	}
	return securefile.WriteFile(cfgPath, out)
}
