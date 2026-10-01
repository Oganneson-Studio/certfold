package config

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
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
	IdentityRenewBefore time.Duration `yaml:"identity_renew_before,omitempty"`
	IPCSocket           string        `yaml:"ipc_socket,omitempty"`
	DataDir             string        `yaml:"data_dir,omitempty"`
}

// IdentitySection holds the PEM-encoded materials needed for mTLS against
// the Certfold server. Populated either by `certfoldc enroll` or by hand.
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
	Format   string   `yaml:"format"`
	Path     string   `yaml:"path"`
	Mode     FileMode `yaml:"mode,omitempty"`
	Owner    string   `yaml:"owner,omitempty"`
	Group    string   `yaml:"group,omitempty"`
	Password string   `yaml:"password,omitempty"` // for pkcs12
}

// FileMode is the permission bits of an output file. client.yaml gives them
// in octal as chmod takes them, with or without a leading 0 or 0o: 640, 0640
// and 0o640 are all 0o640. YAML alone would read 440 as decimal, which is
// 0o670: a valid mode that lets the group write the file.
type FileMode int

// UnmarshalYAML reads the text of the scalar as octal, whatever type YAML
// resolves it to; after ${VAR} expansion the text is the variable's value.
// The Value of a mapping or a sequence is empty, which is not octal.
func (m *FileMode) UnmarshalYAML(n *yaml.Node) error {
	mode, err := strconv.ParseUint(strings.TrimPrefix(n.Value, "0o"), 8, 32)
	if err != nil {
		return &yaml.TypeError{Errors: []string{fmt.Sprintf("line %d: mode %q is not an octal file mode such as 0640", n.Line, n.Value)}}
	}
	*m = FileMode(mode)
	return nil
}

const (
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

	// The client name is the CN of the client certificate and the names of
	// certificates are those of server.yaml, which follow the same rule: a
	// name outside it would never match.
	if c.Client.Name == "" {
		v.Add("client.name", "must be set")
	} else if err := ValidateClientName(c.Client.Name); err != nil {
		v.Add("client.name", "%v", err)
	}
	if c.Client.ServerURL == "" {
		v.Add("client.server_url", "must be set")
	} else if u, err := url.ParseRequestURI(c.Client.ServerURL); err != nil || u.Scheme != "https" {
		v.Add("client.server_url", "must be an https URL")
	}
	if c.Client.IdentityRenewBefore < time.Hour || c.Client.IdentityRenewBefore > 89*24*time.Hour {
		v.Add("client.identity_renew_before", "must be between 1h and 2136h (got %s)", c.Client.IdentityRenewBefore)
	}
	if err := checkAbsolute(c.Client.DataDir); err != nil {
		v.Add("client.data_dir", "%v", err)
	}
	if c.Client.IPCSocket != "" {
		if err := checkAbsolute(c.Client.IPCSocket); err != nil {
			v.Add("client.ipc_socket", "%v", err)
		}
	}

	c.validateIdentity(v)

	// Two outputs at one path would overwrite each other on every reconcile,
	// running their on_change programs each time. Paths are compared as
	// text, after Clean, and in lower case on Windows only. That misses two
	// spellings of one file through a symbolic or hard link; paths differing
	// in case on macOS, whose default APFS ignores case; and, on Windows, the
	// prefixes \\?\ and \\.\ (\\?\C:\x and \\.\C:\x are C:\x), 8.3 short
	// names, the dots and spaces Windows drops from the end of a name, and a
	// mapped drive letter against the UNC path of its share.
	outputPaths := make(map[string]string)
	for _, certName := range slices.Sorted(maps.Keys(c.Certificates)) {
		// An invalid name is reported alone: the paths of the other errors
		// of its entry would quote it.
		if err := ValidateCertificateName(certName); err != nil {
			v.Add("certificates", "%v", err)
			continue
		}
		cert := c.Certificates[certName]
		path := "certificates." + certName
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
			} else if err := checkAbsolute(o.Path); err != nil {
				v.Add(base+".path", "%v", err)
			} else {
				key := filepath.Clean(o.Path)
				if runtime.GOOS == "windows" {
					// NTFS ignores case: Cert.pem and cert.pem are one file.
					key = strings.ToLower(key)
				}
				if prev, dup := outputPaths[key]; dup {
					v.Add(base+".path", "duplicate output path %q (also at %s)", o.Path, prev)
				} else {
					outputPaths[key] = base
				}
			}
			if o.Mode > 0o777 {
				v.Add(base+".mode", "must be a valid octal file mode (got %#o)", o.Mode)
			}
			if o.Format == "pkcs12" && o.Password == "" {
				v.Add(base+".password", "required for pkcs12 format")
			}
		}
		// Whether the program exists is not checked: that can change between
		// runs, and a failed run is reported by certfoldc status.
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
