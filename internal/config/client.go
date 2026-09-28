package config

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"maps"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// ClientConfig is the in-memory representation of client.yaml.
type ClientConfig struct {
	Client       ClientSection                 `yaml:"client"`
	Identity     IdentitySection               `yaml:"identity,omitempty"`
	Certificates map[string]CertificateOutputs `yaml:"certificates,omitempty"`
}

type ClientSection struct {
	Name                string        `yaml:"name"`
	ServerURL           string        `yaml:"server_url"`
	PullInterval        time.Duration `yaml:"pull_interval,omitempty"`
	IdentityRenewBefore time.Duration `yaml:"identity_renew_before,omitempty"`
	PushListen          string        `yaml:"push_listen,omitempty"`
	PushToken           string        `yaml:"push_token,omitempty"`
	IPCSocket           string        `yaml:"ipc_socket,omitempty"`
	DataDir             string        `yaml:"data_dir,omitempty"`
}

// IdentitySection holds the PEM-encoded materials needed for mTLS against
// the Sigil server. Populated either by `sigilc enroll` or by hand.
type IdentitySection struct {
	CACert     string `yaml:"ca_cert,omitempty"`
	ClientCert string `yaml:"client_cert,omitempty"`
	ClientKey  string `yaml:"client_key,omitempty"`
}

// CertificateOutputs is what the client does with one subscribed certificate,
// keyed by its name under certificates in client.yaml.
type CertificateOutputs struct {
	Outputs []OutputSpec `yaml:"outputs"`
	// OnChange is the argv of a program to run after any of Outputs was
	// replaced, starting with its absolute path; it does not go through a
	// shell. Empty, whether absent, null or [], means no program.
	OnChange []string `yaml:"on_change,omitempty"`
}

type OutputSpec struct {
	Format   string `yaml:"format"`
	Path     string `yaml:"path"`
	Mode     int    `yaml:"mode,omitempty"`
	Owner    string `yaml:"owner,omitempty"`
	Group    string `yaml:"group,omitempty"`
	Password string `yaml:"password,omitempty"` // for pkcs12
}

const (
	DefaultPullInterval        = time.Hour
	DefaultIdentityRenewBefore = 30 * 24 * time.Hour
)

// validOutputFormats are the formats the output module can serialize.
var validOutputFormats = map[string]bool{
	"pem-cert":      true,
	"pem-key":       true,
	"pem-fullchain": true,
	"pem-bundle":    true,
	"pkcs12":        true,
	"der":           true,
}

// LoadClient reads client.yaml from path, expands ${VAR} references inside
// its values, applies defaults, and validates.
func LoadClient(path string) (*ClientConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseClient(raw)
}

// ParseClient is LoadClient without filesystem access.
func ParseClient(raw []byte) (*ClientConfig, error) {
	var cfg ClientConfig
	if err := decodeWithEnv(raw, &cfg); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *ClientConfig) applyDefaults() {
	if c.Client.PullInterval == 0 {
		c.Client.PullInterval = DefaultPullInterval
	}
	if c.Client.IdentityRenewBefore == 0 {
		c.Client.IdentityRenewBefore = DefaultIdentityRenewBefore
	}
	if c.Client.DataDir == "" {
		c.Client.DataDir = DefaultClientDataDir()
	}
}

// Validate reports structural problems.
//
// Identity may be empty (e.g. before enroll); when any identity field is
// present, all three must be present and parseable as PEM.
func (c *ClientConfig) Validate() error {
	v := &ValidationError{}

	if strings.TrimSpace(c.Client.Name) == "" {
		v.Add("client.name", "must be set")
	}
	if c.Client.ServerURL == "" {
		v.Add("client.server_url", "must be set")
	} else if u, err := url.ParseRequestURI(c.Client.ServerURL); err != nil || u.Scheme != "https" {
		v.Add("client.server_url", "must be an https URL")
	}
	if c.Client.PullInterval < 30*time.Second {
		v.Add("client.pull_interval", "must be at least 30s (got %s)", c.Client.PullInterval)
	}
	if c.Client.IdentityRenewBefore < time.Hour || c.Client.IdentityRenewBefore > 89*24*time.Hour {
		v.Add("client.identity_renew_before", "must be between 1h and 2136h (got %s)", c.Client.IdentityRenewBefore)
	}
	if err := ValidatePushListen(c.Client.PushListen); err != nil {
		v.Add("client.push_listen", "%v", err)
	}
	if c.Client.PushListen != "" && len(c.Client.PushToken) < 32 {
		v.Add("client.push_token", "must be at least 32 characters when push_listen is enabled")
	}
	if c.Client.PushListen == "" && c.Client.PushToken != "" {
		v.Add("client.push_token", "requires client.push_listen")
	}

	c.validateIdentity(v)

	// Two outputs at one path would overwrite each other on every reconcile,
	// running their on_change programs each time.
	outputPaths := make(map[string]string)
	for _, certName := range slices.Sorted(maps.Keys(c.Certificates)) {
		cert := c.Certificates[certName]
		path := "certificates." + certName
		if certName == "" {
			v.Add("certificates", "certificate name key must not be empty")
		}
		if len(cert.Outputs) == 0 {
			v.Add(path+".outputs", "must have at least one output")
		}
		for i, o := range cert.Outputs {
			base := fmt.Sprintf("%s.outputs[%d]", path, i)
			if !validOutputFormats[o.Format] {
				v.Add(base+".format", "invalid format %q (supported: pem-cert, pem-key, pem-fullchain, pem-bundle, pkcs12, der)", o.Format)
			}
			if o.Path == "" {
				v.Add(base+".path", "must be set")
			} else if prev, dup := outputPaths[filepath.Clean(o.Path)]; dup {
				v.Add(base+".path", "duplicate output path %q (also at %s)", o.Path, prev)
			} else {
				outputPaths[filepath.Clean(o.Path)] = base
			}
			if o.Mode != 0 && (o.Mode < 0 || o.Mode > 0o777) {
				v.Add(base+".mode", "must be a valid octal file mode (got %#o)", o.Mode)
			}
			if o.Format == "pkcs12" && o.Password == "" {
				v.Add(base+".password", "required for pkcs12 format")
			}
		}
		// Whether the program exists is not checked: that can change between
		// runs, and a failed run is reported by sigilc status.
		for i, arg := range cert.OnChange {
			if arg == "" {
				v.Add(fmt.Sprintf("%s.on_change[%d]", path, i), "must not be empty")
			} else if i == 0 && !filepath.IsAbs(arg) {
				v.Add(path+".on_change[0]", "must be an absolute program path, got %q", arg)
			}
		}
	}

	return v.ErrOrNil()
}

// ValidatePushListen ensures the plaintext push receiver can only bind to a
// literal loopback address. Hostnames are intentionally rejected so DNS or
// hosts-file changes cannot move the listener onto a non-loopback interface.
func ValidatePushListen(addr string) error {
	if addr == "" {
		return nil
	}
	parsed, err := netip.ParseAddrPort(addr)
	if err != nil || !parsed.Addr().Unmap().IsLoopback() || parsed.Port() == 0 {
		return fmt.Errorf("must use a loopback IP and port 1-65535 (for example 127.0.0.1:9443 or [::1]:9443)")
	}
	return nil
}

func (c *ClientConfig) validateIdentity(v *ValidationError) {
	id := c.Identity
	present := 0
	if id.CACert != "" {
		present++
	}
	if id.ClientCert != "" {
		present++
	}
	if id.ClientKey != "" {
		present++
	}
	if present == 0 {
		return // pre-enroll state, fine
	}
	if present != 3 {
		v.Add("identity", "ca_cert, client_cert, and client_key must all be present (or all absent)")
		return
	}
	if !isValidPEM(id.CACert, "CERTIFICATE") {
		v.Add("identity.ca_cert", "is not a valid PEM-encoded certificate")
	} else if _, err := parseFirstCert([]byte(id.CACert)); err != nil {
		v.Add("identity.ca_cert", "could not parse certificate: %v", err)
	}
	if !isValidPEM(id.ClientCert, "CERTIFICATE") {
		v.Add("identity.client_cert", "is not a valid PEM-encoded certificate")
	} else if _, err := parseFirstCert([]byte(id.ClientCert)); err != nil {
		v.Add("identity.client_cert", "could not parse certificate: %v", err)
	}
	if !isValidPEM(id.ClientKey, "PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY") {
		v.Add("identity.client_key", "is not a valid PEM-encoded private key")
	}
}

func isValidPEM(s string, allowedTypes ...string) bool {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return false
	}
	for _, t := range allowedTypes {
		if block.Type == t {
			return true
		}
	}
	return false
}

func parseFirstCert(b []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("no PEM data")
	}
	return x509.ParseCertificate(block.Bytes)
}
