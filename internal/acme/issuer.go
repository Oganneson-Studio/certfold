package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/alidns"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/gcloud"
	"github.com/go-acme/lego/v4/providers/dns/route53"
	"github.com/go-acme/lego/v4/providers/dns/tencentcloud"
	"github.com/go-acme/lego/v4/registration"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

// Bounds on one issuance. lego's API takes no context, so timeouts are what
// stop a stalled ACME server or DNS provider from blocking issuance forever.
//
// lego.NewConfig already bounds the ACME side with fixed values that no
// environment variable changes: 2 minutes per request to the ACME server and
// 30 seconds of waiting for the certificate after the order is finalized.
//
// The DNS values below replace lego's per-provider defaults, which lego reads
// from environment variables such as CLOUDFLARE_PROPAGATION_TIMEOUT without
// any upper limit. None is lower than lego's own default.
//
// lego does not let Sigil bound everything:
//   - lego builds the gcloud provider's configuration itself, so it keeps
//     lego's defaults (180 s propagation, 5 s polling, read from
//     GCE_PROPAGATION_TIMEOUT and GCE_POLLING_INTERVAL), and like route53
//     (AWS SDK) it uses an HTTP client without an overall timeout;
//   - after a challenge is submitted, lego polls the authorization for up to
//     100 times the CA's Retry-After (500 s when the CA sends none).
const (
	// dnsAPITimeout bounds each request to the DNS provider's API.
	dnsAPITimeout = 30 * time.Second
	// dnsPropagationTimeout bounds the wait, per domain, for the challenge TXT
	// record to reach the authoritative name servers. route53 also uses it to
	// wait for its change to become INSYNC.
	dnsPropagationTimeout = 2 * time.Minute
	// dnsPollingInterval is how often propagation is checked.
	dnsPollingInterval = 4 * time.Second
)

// SetDNSResolvers makes the DNS lookups of DNS-01 challenges (zone lookup,
// CNAME following, propagation check) use resolvers, each "host" or
// "host:port", instead of lego's default. An empty list keeps the default.
//
// lego v4.35.2 keeps the recursive nameservers in a package-level variable,
// and the dns01.AddRecursiveNameservers option does not use the Challenge it
// is given, so the setting is process-wide: set it once at startup, before
// any issuance runs.
func SetDNSResolvers(resolvers []string) {
	if len(resolvers) == 0 {
		return
	}
	_ = dns01.AddRecursiveNameservers(resolvers)(nil)
}

// Result holds the output of a successful certificate issuance.
type Result struct {
	Domain      string
	Certificate []byte // fullchain PEM (cert + intermediates)
	PrivateKey  []byte // PEM
	IssuerCert  []byte // issuer PEM
	NotAfter    time.Time
}

// Issuer wraps lego to issue/renew certificates per CertificateSpec.
type Issuer struct {
	accounts *store.AccountRepo
}

// NewIssuer creates an Issuer backed by the persistent ACME account store.
func NewIssuer(accounts *store.AccountRepo) *Issuer { return &Issuer{accounts: accounts} }

// Issue requests a certificate for the given spec from its configured CA.
// cfg and spec must come from the same validated runtime configuration
// snapshot.
//
// ctx is used only for the account store. lego's API takes no context, so
// cancelling ctx does not interrupt a running ACME exchange; the timeouts
// described at the top of this file bound it instead. sigils waits for the
// scheduler's in-flight Issue during shutdown, so those timeouts also bound
// how long issuance can delay shutdown.
func (i *Issuer) Issue(ctx context.Context, cfg *config.ServerConfig, spec config.CertificateSpec) (*Result, error) {
	caEntry, ok := cfg.ACME.CAs[spec.CA]
	if !ok {
		return nil, fmt.Errorf("unknown CA %q", spec.CA)
	}

	userKey, err := i.loadOrCreateAccountKey(ctx, spec.CA, caEntry.Directory, cfg.ACME.Email)
	if err != nil {
		return nil, fmt.Errorf("account key: %w", err)
	}

	u := &legoUser{
		email: cfg.ACME.Email,
		key:   userKey,
	}

	// Load persisted registration if present.
	reg, err := i.loadRegistration(ctx, spec.CA, caEntry.Directory, cfg.ACME.Email)
	if err == nil {
		u.reg = reg
	}

	legoCfg := lego.NewConfig(u)
	legoCfg.CADirURL = caEntry.Directory
	legoCfg.Certificate.KeyType = specKeyType(spec.KeyType)

	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return nil, fmt.Errorf("lego client: %w", err)
	}

	// Register account if we don't have one yet.
	if u.reg == nil {
		if err := i.register(ctx, client, u, spec.CA, caEntry, cfg.ACME.Email); err != nil {
			return nil, fmt.Errorf("register: %w", err)
		}
	}

	// Configure DNS provider.
	dnsP, ok := cfg.DNSProviders[spec.DNSProvider]
	if !ok {
		return nil, fmt.Errorf("unknown DNS provider %q", spec.DNSProvider)
	}
	provider, err := buildDNSProvider(dnsP)
	if err != nil {
		return nil, fmt.Errorf("dns provider %q: %w", spec.DNSProvider, err)
	}
	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return nil, fmt.Errorf("set dns01 provider: %w", err)
	}

	req := certificate.ObtainRequest{
		Domains: spec.Domains,
		Bundle:  true,
	}
	res, err := client.Certificate.Obtain(req)
	if err != nil {
		return nil, fmt.Errorf("obtain certificate: %w", err)
	}

	notAfter := certNotAfter(res.Certificate)
	return &Result{
		Domain:      res.Domain,
		Certificate: res.Certificate,
		PrivateKey:  res.PrivateKey,
		IssuerCert:  res.IssuerCertificate,
		NotAfter:    notAfter,
	}, nil
}

// ---------------------------------------------------------------------------
// Account management
// ---------------------------------------------------------------------------

func (i *Issuer) loadOrCreateAccountKey(ctx context.Context, ca, directory, email string) (*ecdsa.PrivateKey, error) {
	rec, err := i.accounts.Get(ctx, ca, nil)
	if err == nil && rec.Directory == directory && rec.Email == email && rec.KeyPEM != "" {
		return parseECDSAKey([]byte(rec.KeyPEM))
	}
	// Generate a new key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	newRec := &store.AccountRecord{
		CA:        ca,
		Directory: directory,
		Email:     email,
		KeyPEM:    keyPEM,
	}
	if err := i.accounts.Upsert(ctx, newRec, nil); err != nil {
		return nil, fmt.Errorf("persist account key: %w", err)
	}
	return key, nil
}

func (i *Issuer) loadRegistration(ctx context.Context, ca, directory, email string) (*registration.Resource, error) {
	rec, err := i.accounts.Get(ctx, ca, nil)
	if err != nil || rec.Directory != directory || rec.Email != email || rec.RegistrationJSON == "" {
		return nil, fmt.Errorf("no registration")
	}
	var reg registration.Resource
	if err := json.Unmarshal([]byte(rec.RegistrationJSON), &reg); err != nil {
		return nil, err
	}
	return &reg, nil
}

func (i *Issuer) register(ctx context.Context, client *lego.Client, u *legoUser, ca string, caEntry config.CAEntry, email string) error {
	var reg *registration.Resource
	var err error
	if caEntry.EABKID != "" {
		reg, err = client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:                  caEntry.EABKID,
			HmacEncoded:          caEntry.EABHMAC,
		})
	} else {
		reg, err = client.Registration.Register(registration.RegisterOptions{
			TermsOfServiceAgreed: true,
		})
	}
	if err != nil {
		return err
	}
	u.reg = reg

	regJSON, err := json.Marshal(reg)
	if err != nil {
		return err
	}
	rec, _ := i.accounts.Get(ctx, ca, nil)
	if rec == nil {
		rec = &store.AccountRecord{CA: ca, Directory: caEntry.Directory, Email: email}
	}
	rec.Directory = caEntry.Directory
	rec.Email = email
	rec.RegistrationJSON = string(regJSON)
	return i.accounts.Upsert(ctx, rec, nil)
}

// ---------------------------------------------------------------------------
// legoUser implements registration.User
// ---------------------------------------------------------------------------

type legoUser struct {
	email string
	key   *ecdsa.PrivateKey
	reg   *registration.Resource
}

func (u *legoUser) GetEmail() string                        { return u.email }
func (u *legoUser) GetRegistration() *registration.Resource { return u.reg }
func (u *legoUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// ---------------------------------------------------------------------------
// DNS provider builder
// ---------------------------------------------------------------------------

func buildDNSProvider(p config.DNSProvider) (challenge.Provider, error) {
	cfg := p.Config
	switch p.Type {
	case "cloudflare":
		c := cloudflare.NewDefaultConfig()
		c.PropagationTimeout, c.PollingInterval = dnsPropagationTimeout, dnsPollingInterval
		c.HTTPClient.Timeout = dnsAPITimeout
		if v, ok := cfg["api_token"].(string); ok {
			c.AuthToken = v
		}
		if v, ok := cfg["zone_api_token"].(string); ok {
			c.ZoneToken = v
		}
		if v, ok := cfg["auth_email"].(string); ok {
			c.AuthEmail = v
		}
		if v, ok := cfg["auth_key"].(string); ok {
			c.AuthKey = v
		}
		return cloudflare.NewDNSProviderConfig(c)

	case "aliyun":
		c := alidns.NewDefaultConfig()
		c.PropagationTimeout, c.PollingInterval = dnsPropagationTimeout, dnsPollingInterval
		c.HTTPTimeout = dnsAPITimeout
		if v, ok := cfg["access_key"].(string); ok {
			c.APIKey = v
		}
		if v, ok := cfg["access_secret"].(string); ok {
			c.SecretKey = v
		}
		return alidns.NewDNSProviderConfig(c)

	case "tencentcloud":
		c := tencentcloud.NewDefaultConfig()
		c.PropagationTimeout, c.PollingInterval = dnsPropagationTimeout, dnsPollingInterval
		c.HTTPTimeout = dnsAPITimeout
		if v, ok := cfg["secret_id"].(string); ok {
			c.SecretID = v
		}
		if v, ok := cfg["secret_key"].(string); ok {
			c.SecretKey = v
		}
		return tencentcloud.NewDNSProviderConfig(c)

	case "route53":
		c := route53.NewDefaultConfig()
		c.PropagationTimeout, c.PollingInterval = dnsPropagationTimeout, dnsPollingInterval
		if v, ok := cfg["access_key"].(string); ok {
			c.AccessKeyID = v
		}
		if v, ok := cfg["secret_key"].(string); ok {
			c.SecretAccessKey = v
		}
		if v, ok := cfg["region"].(string); ok {
			c.Region = v
		}
		return route53.NewDNSProviderConfig(c)

	case "gcloud":
		if v, ok := cfg["service_account_file"].(string); ok && v != "" {
			return gcloud.NewDNSProviderServiceAccount(v)
		}
		// Application default credentials for the configured project.
		project, _ := cfg["project"].(string)
		return gcloud.NewDNSProviderCredentials(project)

	default:
		return nil, fmt.Errorf("unsupported provider type %q", p.Type)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func specKeyType(kt string) certcrypto.KeyType {
	switch kt {
	case "rsa2048":
		return certcrypto.RSA2048
	case "rsa4096":
		return certcrypto.RSA4096
	case "ec384":
		return certcrypto.EC384
	default: // ec256
		return certcrypto.EC256
	}
}

func parseECDSAKey(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not ECDSA")
	}
	return ecKey, nil
}

func certNotAfter(certPEM []byte) time.Time {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}
	}
	return cert.NotAfter
}
