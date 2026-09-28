package config

import (
	"fmt"
	"maps"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// ServerConfig is the in-memory representation of server.yaml.
type ServerConfig struct {
	Server       ServerSection          `yaml:"server"`
	ACME         ACMESection            `yaml:"acme"`
	DNSProviders map[string]DNSProvider `yaml:"dns_providers"`
	Certificates []CertificateSpec      `yaml:"certificates"`
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
	// DNSResolvers, each "host" or "host:port", replace lego's default
	// resolvers (/etc/resolv.conf, else Google Public DNS, as on Windows) for
	// the DNS lookups of DNS-01 challenges. lego keeps them process-wide, so
	// changing them requires a restart.
	DNSResolvers []string `yaml:"dns_resolvers,omitempty"`
}

type CAEntry struct {
	Directory string `yaml:"directory"`
	EABKID    string `yaml:"eab_kid,omitempty"`
	EABHMAC   string `yaml:"eab_hmac,omitempty"`
}

// DNSProvider is intentionally loose: each provider type accepts different
// fields. We unmarshal into a generic map and validate per-type at load.
type DNSProvider struct {
	Type string `yaml:"type"`
	// Command is the argv of the program an exec provider runs, starting with
	// its absolute path. Only type exec accepts it.
	Command []string `yaml:"command,omitempty"`
	// SkipPropagationCheck hands the challenge to the CA without first
	// checking that the TXT record has reached the zone's authoritative name
	// servers.
	SkipPropagationCheck bool           `yaml:"skip_propagation_check,omitempty"`
	Config               map[string]any `yaml:",inline"`
}

// CertificateSpec is a certificate that sigils issues. When it is renewed is
// not configured: the scheduler renews a certificate when a share of its
// lifetime is left.
type CertificateSpec struct {
	Name        string   `yaml:"name"`
	Domains     []string `yaml:"domains"`
	CA          string   `yaml:"ca"`
	DNSProvider string   `yaml:"dns_provider"`
	KeyType     string   `yaml:"key_type,omitempty"`
	Subscribers []string `yaml:"subscribers,omitempty"`
}

const (
	DefaultListen  = ":8443"
	DefaultKeyType = "ec256"
)

// validKeyTypes are the key algorithms the ACME issuer understands.
var validKeyTypes = map[string]bool{
	"rsa2048": true,
	"rsa4096": true,
	"ec256":   true,
	"ec384":   true,
}

// validDNSProviderTypes is the closed set of DNS provider types Sigil
// supports out of the box. Each value except exec corresponds to a lego
// provider package; exec runs the program given by command.
var validDNSProviderTypes = map[string]bool{
	"cloudflare":   true,
	"aliyun":       true,
	"tencentcloud": true,
	"route53":      true,
	"gcloud":       true,
	"exec":         true,
}

// LoadServer reads server.yaml from path, expands ${VAR} references inside
// its values against the process environment, applies defaults, and
// validates.
func LoadServer(path string) (*ServerConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseServer(raw)
}

// ParseServer is LoadServer without filesystem access (useful for tests).
func ParseServer(raw []byte) (*ServerConfig, error) {
	var cfg ServerConfig
	if err := decodeWithEnv(raw, &cfg); err != nil {
		return nil, err
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
// caller's environment. The two values are expanded exactly as LoadServer
// expands them. Empty results mean the field is not set.
func ReadServerPaths(path string) (dataDir, ipcSocket string, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", "", fmt.Errorf("read %s: %w", path, err)
	}
	var doc struct {
		Server struct {
			DataDir   yaml.Node `yaml:"data_dir"`
			IPCSocket yaml.Node `yaml:"ipc_socket"`
		} `yaml:"server"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return "", "", fmt.Errorf("parse %s: %w", path, err)
	}
	if dataDir, err = expandedString(&doc.Server.DataDir, "server.data_dir"); err != nil {
		return "", "", err
	}
	if ipcSocket, err = expandedString(&doc.Server.IPCSocket, "server.ipc_socket"); err != nil {
		return "", "", err
	}
	return dataDir, ipcSocket, nil
}

// expandedString expands the value node n at path as LoadServer does and
// decodes it as a string. An absent value decodes as "".
func expandedString(n *yaml.Node, path string) (string, error) {
	for n.Kind == yaml.AliasNode {
		n = n.Alias
	}
	// Expand a copy: both paths may alias the same anchored node.
	value := *n
	if err := expandEnvNode(&value, path); err != nil {
		return "", err
	}
	var s string
	if err := value.Decode(&s); err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

func (c *ServerConfig) applyDefaults() {
	if c.Server.Listen == "" {
		c.Server.Listen = DefaultListen
	}
	for i := range c.Certificates {
		if c.Certificates[i].KeyType == "" {
			c.Certificates[i].KeyType = DefaultKeyType
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
		} else if i := strings.IndexFunc(c.Server.PublicURL, unquotable); i >= 0 {
			r, _ := utf8.DecodeRuneInString(c.Server.PublicURL[i:])
			v.Add("server.public_url", "must not contain %q: install commands quote the URL for sh and PowerShell", r)
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
	for i, resolver := range c.ACME.DNSResolvers {
		if !isValidDNSResolver(resolver) {
			v.Add(fmt.Sprintf("acme.dns_resolvers[%d]", i), "invalid DNS resolver %q (want host or host:port)", resolver)
		}
	}

	for name, p := range c.DNSProviders {
		path := fmt.Sprintf("dns_providers.%s", name)
		if p.Type == "" {
			v.Add(path+".type", "must be set")
		} else if !validDNSProviderTypes[p.Type] {
			v.Add(path+".type", "unknown DNS provider type %q (supported: cloudflare, aliyun, tencentcloud, route53, gcloud, exec)", p.Type)
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
	}

	// Subscribers reference clients that *might* not be enrolled yet — that's
	// allowed (you typically write subscribers first, then enroll). We only
	// validate that subscriber names are valid client names; the API matches
	// them against certificate CNs exactly.
	for i, cert := range c.Certificates {
		for j, sub := range cert.Subscribers {
			if err := ValidateClientName(sub); err != nil {
				v.Add(fmt.Sprintf("certificates[%d].subscribers[%d]", i, j), "%v", err)
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

	if p.Type != "exec" && len(p.Command) > 0 {
		v.Add(path+".command", "only valid for provider type \"exec\"")
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
		// Without a service account file the issuer uses application default
		// credentials for the configured project; lego does not detect the
		// project on that path, so one of the two must be set.
		if strField("project") == "" && strField("service_account_file") == "" {
			v.Add(path, "gcloud provider requires project (used with application default credentials) or service_account_file")
		}
	case "exec":
		// The inline map takes any key, so KnownFields cannot catch a typo
		// such as "comand". exec has only typed fields: reject every other key.
		for _, key := range slices.Sorted(maps.Keys(p.Config)) {
			v.Add(fmt.Sprintf("%s.%s", path, key), "unknown field for provider type %q", p.Type)
		}
		// Whether the program exists is not checked: that can change between
		// runs, and a failed run is reported as the certificate's last error.
		if len(p.Command) == 0 {
			v.Add(path+".command", "required for provider type %q", p.Type)
		}
		for i, arg := range p.Command {
			if arg == "" {
				v.Add(fmt.Sprintf("%s.command[%d]", path, i), "must not be empty")
			} else if i == 0 && !filepath.IsAbs(arg) {
				v.Add(path+".command[0]", "must be an absolute program path, got %q", arg)
			}
		}
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

// unquotable reports whether r may not appear in server.public_url, which the
// install commands put between single quotes for sh and for PowerShell: any
// character but ASCII, and quotes, backticks, "$", "\", whitespace and control
// characters. PowerShell takes U+2018 to U+201B for single quotes and U+201C
// to U+201E for double quotes, hence ASCII only.
func unquotable(r rune) bool {
	return r > unicode.MaxASCII || unicode.IsSpace(r) || unicode.IsControl(r) || strings.ContainsRune("'\"`$\\", r)
}

// isValidDNSResolver reports whether s works as a resolver address after
// lego's dns01.ParseNameservers adds the default port 53 to it, which lego
// does whenever net.SplitHostPort fails on s.
func isValidDNSResolver(s string) bool {
	addr := s
	if _, _, err := net.SplitHostPort(s); err != nil {
		addr = net.JoinHostPort(s, "53")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || strings.ContainsFunc(host, func(r rune) bool {
		return r == '/' || unicode.IsSpace(r)
	}) {
		return false
	}
	n, err := strconv.ParseUint(port, 10, 16)
	return err == nil && n > 0
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
