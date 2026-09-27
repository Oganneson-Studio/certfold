package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ServerConfig is the in-memory representation of server.yaml.
type ServerConfig struct {
	Server       ServerSection          `yaml:"server"`
	ACME         ACMESection            `yaml:"acme"`
	DNSProviders map[string]DNSProvider `yaml:"dns_providers"`
	Certificates []CertificateSpec      `yaml:"certificates"`
	Clients      []ClientRegistration   `yaml:"clients,omitempty"`
}

type ServerSection struct {
	Listen      string `yaml:"listen"`
	DataDir     string `yaml:"data_dir"`
	TLSCertFile string `yaml:"tls_cert_file,omitempty"`
	TLSKeyFile  string `yaml:"tls_key_file,omitempty"`
	// PublicURL is the externally reachable base URL clients use to reach this
	// server (e.g. https://sigil.example.com:8443). Required when the listen
	// address is not a resolvable hostname (e.g. ":8443").
	PublicURL string `yaml:"public_url,omitempty"`
	// IPCSocket optionally overrides the default IPC endpoint
	// (Unix socket path on Linux/macOS, named pipe name on Windows).
	IPCSocket string `yaml:"ipc_socket,omitempty"`
}

type ACMESection struct {
	Email     string             `yaml:"email"`
	DefaultCA string             `yaml:"default_ca"`
	CAs       map[string]CAEntry `yaml:"cas"`
}

type CAEntry struct {
	Directory string `yaml:"directory"`
	EABKID    string `yaml:"eab_kid,omitempty"`
	EABHMAC   string `yaml:"eab_hmac,omitempty"`
}

// DNSProvider is intentionally loose: each provider type accepts different
// fields. We unmarshal into a generic map and validate per-type at load.
type DNSProvider struct {
	Type   string         `yaml:"type"`
	Config map[string]any `yaml:",inline"`
}

type CertificateSpec struct {
	Name            string   `yaml:"name"`
	Domains         []string `yaml:"domains"`
	CA              string   `yaml:"ca"`
	DNSProvider     string   `yaml:"dns_provider"`
	KeyType         string   `yaml:"key_type,omitempty"`
	RenewDaysBefore int      `yaml:"renew_days_before,omitempty"`
	Subscribers     []string `yaml:"subscribers,omitempty"`
}

type ClientRegistration struct {
	Name         string    `yaml:"name"`
	Fingerprint  string    `yaml:"fingerprint"`
	EnrolledAt   time.Time `yaml:"enrolled_at"`
	PushEndpoint string    `yaml:"push_endpoint,omitempty"`
	PushToken    string    `yaml:"push_token,omitempty"`
}

const (
	DefaultListen          = ":8443"
	DefaultKeyType         = "ec256"
	DefaultRenewDaysBefore = 30
)

// validKeyTypes are the key algorithms the ACME issuer understands.
var validKeyTypes = map[string]bool{
	"rsa2048": true,
	"rsa4096": true,
	"ec256":   true,
	"ec384":   true,
}

// validDNSProviderTypes is the closed set of DNS provider types Sigil
// supports out of the box. Each value corresponds to a lego provider package.
var validDNSProviderTypes = map[string]bool{
	"cloudflare":   true,
	"aliyun":       true,
	"tencentcloud": true,
	"route53":      true,
	"gcloud":       true,
}

// LoadServer reads server.yaml from path, expands ${VAR} substitutions
// against the process environment, applies defaults, and validates.
func LoadServer(path string) (*ServerConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseServer(raw)
}

// ParseServer is LoadServer without filesystem access (useful for tests).
func ParseServer(raw []byte) (*ServerConfig, error) {
	expanded, err := expandEnv(raw, nil)
	if err != nil {
		return nil, fmt.Errorf("expand env: %w", err)
	}
	var cfg ServerConfig
	dec := yaml.NewDecoder(strings.NewReader(string(expanded)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// ReadServerPaths reads server.data_dir and server.ipc_socket from the
// server.yaml at path so CLI commands can locate the daemon. Unlike LoadServer
// it expands ${VAR} only in these two values and does not validate the file,
// so the DNS credentials other sections reference need not be set in the
// caller's environment. Empty results mean the field is not set.
func ReadServerPaths(path string) (dataDir, ipcSocket string, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", "", fmt.Errorf("read %s: %w", path, err)
	}
	var doc struct {
		Server struct {
			DataDir   string `yaml:"data_dir"`
			IPCSocket string `yaml:"ipc_socket"`
		} `yaml:"server"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return "", "", fmt.Errorf("parse %s: %w", path, err)
	}
	expandedDataDir, err := expandEnv([]byte(doc.Server.DataDir), nil)
	if err != nil {
		return "", "", fmt.Errorf("server.data_dir: %w", err)
	}
	expandedIPCSocket, err := expandEnv([]byte(doc.Server.IPCSocket), nil)
	if err != nil {
		return "", "", fmt.Errorf("server.ipc_socket: %w", err)
	}
	return string(expandedDataDir), string(expandedIPCSocket), nil
}

func (c *ServerConfig) applyDefaults() {
	if c.Server.Listen == "" {
		c.Server.Listen = DefaultListen
	}
	for i := range c.Certificates {
		if c.Certificates[i].KeyType == "" {
			c.Certificates[i].KeyType = DefaultKeyType
		}
		if c.Certificates[i].RenewDaysBefore == 0 {
			c.Certificates[i].RenewDaysBefore = DefaultRenewDaysBefore
		}
	}
}

// Validate reports any structural problems in c.
func (c *ServerConfig) Validate() error {
	v := &ValidationError{}

	if strings.TrimSpace(c.Server.DataDir) == "" {
		v.Add("server.data_dir", "must be set")
	}
	if !isValidListen(c.Server.Listen) {
		v.Add("server.listen", "invalid listen address %q", c.Server.Listen)
	}
	if (c.Server.TLSCertFile == "") != (c.Server.TLSKeyFile == "") {
		v.Add("server.tls", "tls_cert_file and tls_key_file must be set together")
	}
	if c.Server.PublicURL != "" {
		if u, err := url.ParseRequestURI(c.Server.PublicURL); err != nil || u.Scheme != "https" {
			v.Add("server.public_url", "must be an https URL, got %q", c.Server.PublicURL)
		}
	}

	if strings.TrimSpace(c.ACME.Email) == "" {
		v.Add("acme.email", "must be set")
	} else if !strings.Contains(c.ACME.Email, "@") {
		v.Add("acme.email", "not a valid email address: %q", c.ACME.Email)
	}
	if len(c.ACME.CAs) == 0 {
		v.Add("acme.cas", "at least one CA must be defined")
	}
	for name, ca := range c.ACME.CAs {
		path := fmt.Sprintf("acme.cas.%s", name)
		if _, err := url.ParseRequestURI(ca.Directory); err != nil || !strings.HasPrefix(ca.Directory, "https://") {
			v.Add(path+".directory", "must be an https URL")
		}
		if (ca.EABKID == "") != (ca.EABHMAC == "") {
			v.Add(path, "eab_kid and eab_hmac must be set together")
		}
	}
	if c.ACME.DefaultCA == "" {
		v.Add("acme.default_ca", "must be set")
	} else if _, ok := c.ACME.CAs[c.ACME.DefaultCA]; !ok {
		v.Add("acme.default_ca", "references unknown CA %q", c.ACME.DefaultCA)
	}

	for name, p := range c.DNSProviders {
		path := fmt.Sprintf("dns_providers.%s", name)
		if p.Type == "" {
			v.Add(path+".type", "must be set")
		} else if !validDNSProviderTypes[p.Type] {
			v.Add(path+".type", "unknown DNS provider type %q (supported: cloudflare, aliyun, tencentcloud, route53, gcloud)", p.Type)
		} else {
			validateDNSProviderFields(v, path, p)
		}
	}

	seen := make(map[string]int, len(c.Certificates))
	for i, cert := range c.Certificates {
		base := fmt.Sprintf("certificates[%d]", i)
		if cert.Name == "" {
			v.Add(base+".name", "must be set")
		} else if prev, dup := seen[cert.Name]; dup {
			v.Add(base+".name", "duplicate certificate name %q (also at certificates[%d])", cert.Name, prev)
		} else {
			seen[cert.Name] = i
		}
		if len(cert.Domains) == 0 {
			v.Add(base+".domains", "at least one domain is required")
		}
		for j, d := range cert.Domains {
			if !isValidDomain(d) {
				v.Add(fmt.Sprintf("%s.domains[%d]", base, j), "invalid domain %q", d)
			}
		}
		if cert.CA == "" {
			v.Add(base+".ca", "must be set")
		} else if _, ok := c.ACME.CAs[cert.CA]; !ok {
			v.Add(base+".ca", "references unknown CA %q", cert.CA)
		}
		if cert.DNSProvider == "" {
			v.Add(base+".dns_provider", "must be set")
		} else if _, ok := c.DNSProviders[cert.DNSProvider]; !ok {
			v.Add(base+".dns_provider", "references unknown DNS provider %q", cert.DNSProvider)
		}
		if !validKeyTypes[cert.KeyType] {
			v.Add(base+".key_type", "invalid key_type %q (supported: rsa2048, rsa4096, ec256, ec384)", cert.KeyType)
		}
		if cert.RenewDaysBefore < 1 || cert.RenewDaysBefore > 89 {
			v.Add(base+".renew_days_before", "must be between 1 and 89 (got %d)", cert.RenewDaysBefore)
		}
	}

	clientNames := make(map[string]bool, len(c.Clients))
	for i, cl := range c.Clients {
		base := fmt.Sprintf("clients[%d]", i)
		if cl.Name == "" {
			v.Add(base+".name", "must be set")
		} else if clientNames[cl.Name] {
			v.Add(base+".name", "duplicate client name %q", cl.Name)
		} else {
			clientNames[cl.Name] = true
		}
		if cl.PushEndpoint != "" {
			u, err := url.ParseRequestURI(cl.PushEndpoint)
			if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
				v.Add(base+".push_endpoint", "must be an https URL without credentials, query, or fragment")
			}
		}
		if cl.PushEndpoint == "" && cl.PushToken != "" {
			v.Add(base+".push_token", "requires push_endpoint")
		}
		if cl.PushEndpoint != "" && len(cl.PushToken) < 32 {
			v.Add(base+".push_token", "must be at least 32 characters when push_endpoint is set")
		}
	}

	// Subscribers reference clients that *might* not be enrolled yet — that's
	// allowed (you typically write subscribers first, then enroll). We only
	// validate that subscriber names are syntactically reasonable.
	for i, cert := range c.Certificates {
		for j, sub := range cert.Subscribers {
			if sub == "" {
				v.Add(fmt.Sprintf("certificates[%d].subscribers[%d]", i, j), "must not be empty")
			}
		}
	}

	return v.ErrOrNil()
}

// validateDNSProviderFields checks that per-type required fields are present.
func validateDNSProviderFields(v *ValidationError, path string, p DNSProvider) {
	strField := func(key string) string {
		if val, ok := p.Config[key].(string); ok {
			return val
		}
		return ""
	}
	requireField := func(key string) {
		if strField(key) == "" {
			v.Add(fmt.Sprintf("%s.%s", path, key), "required for provider type %q", p.Type)
		}
	}

	switch p.Type {
	case "cloudflare":
		// Either api_token (recommended) or auth_email+auth_key must be set.
		hasToken := strField("api_token") != ""
		hasLegacy := strField("auth_email") != "" && strField("auth_key") != ""
		if !hasToken && !hasLegacy {
			v.Add(path, "cloudflare provider requires api_token, or both auth_email and auth_key")
		}
	case "aliyun":
		requireField("access_key")
		requireField("access_secret")
	case "tencentcloud":
		requireField("secret_id")
		requireField("secret_key")
	case "route53":
		// route53 can use IAM instance roles (no explicit keys required),
		// but if access_key is set then secret_key must also be set.
		hasKey := strField("access_key") != ""
		hasSecret := strField("secret_key") != ""
		if hasKey != hasSecret {
			v.Add(path, "route53 provider requires both access_key and secret_key (or neither for IAM role)")
		}
	case "gcloud":
		// gcloud can use ADC (no explicit field required),
		// but service_account_file or project should ideally be set.
		// We only enforce that if service_account_file is set it is non-empty
		// (it already is non-empty by the check above); nothing more to require.
	}
}

// PublicBaseURL returns the externally reachable base URL for this server.
// It prefers server.public_url; otherwise it derives one from server.listen.
// The result always has no trailing slash.
func (c *ServerConfig) PublicBaseURL() string {
	if c.Server.PublicURL != "" {
		return strings.TrimRight(c.Server.PublicURL, "/")
	}
	// Best-effort: wrap listen address with https scheme.
	return "https://" + strings.TrimLeft(c.Server.Listen, ":")
}

func isValidListen(addr string) bool {
	if addr == "" {
		return false
	}
	// Accept ":8443", "0.0.0.0:8443", "[::]:8443", "host:port".
	return strings.Contains(addr, ":")
}

func isValidDomain(d string) bool {
	if d == "" || len(d) > 253 {
		return false
	}
	// allow "*." wildcard prefix
	core := d
	if strings.HasPrefix(core, "*.") {
		core = core[2:]
	}
	if core == "" {
		return false
	}
	for _, label := range strings.Split(core, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			if !(r == '-' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
				return false
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}
