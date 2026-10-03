package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
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
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	gdns "google.golang.org/api/dns/v1"

	"github.com/Oganneson-Studio/certfold/internal/config"
	"github.com/Oganneson-Studio/certfold/internal/store"
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
// any upper limit. None is lower than lego's own default. The exec provider
// uses them too, and each run of its program is bounded by dnsHookTimeout
// (dns_exec.go).
//
// lego does not let Certfold bound everything:
//   - route53 uses the AWS SDK's HTTP client, which has no overall timeout;
//   - each DNS query of the DNS-01 lookups (CNAME following, zone and name
//     server lookups, the propagation check) waits up to lego's fixed 10 s
//     (20 s on Windows) per resolver, trying the resolvers in turn; the
//     CNAME lookups run outside the propagation timeout, and that timeout is
//     only checked between attempts;
//   - after a challenge is submitted, lego polls the authorization for up to
//     100 times the CA's Retry-After (500 s when the CA sends none).
const (
	// dnsAPITimeout bounds each request to the DNS provider's API, and for
	// gcloud each request for an access token too (except to the GCE metadata
	// server, whose client is the metadata package's own).
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

// accountStore is the subset of store.AccountRepo used by Issuer.
type accountStore interface {
	Get(ctx context.Context, ca string, tx *sql.Tx) (*store.AccountRecord, error)
	Upsert(ctx context.Context, rec *store.AccountRecord, tx *sql.Tx) error
}

// Issuer wraps lego to issue/renew certificates per CertificateSpec.
type Issuer struct {
	// programs ends the programs of exec DNS providers: lego's provider API
	// takes no context.
	programs context.Context
	accounts accountStore
	// accountLocks maps a CA name to the *sync.Mutex that serializes the
	// initialization of its ACME account; see accountClient.
	accountLocks sync.Map
}

// NewIssuer creates an Issuer backed by the persistent ACME account store.
// When ctx ends, the programs of exec DNS providers still running are killed
// along with the processes they started. It must end with the daemon, not
// with the scheduler or a request: certfolds ends it when shutdown gives up on
// the issuances still running, so that those finishing in time can still
// clean up their DNS records.
func NewIssuer(ctx context.Context, accounts *store.AccountRepo) *Issuer {
	return &Issuer{programs: ctx, accounts: accounts}
}

// Issue requests a certificate for the given spec from its configured CA.
// cfg and spec must come from the same validated runtime configuration
// snapshot. replacing, the fullchain PEM of the certificate this one
// replaces, or nil, names that certificate in the order (RFC 9773, section
// 5) when it has an authority key identifier. lego sends it only to a CA
// that offers renewal information, and orders again without it when the CA
// answers that the certificate was replaced already.
//
// ctx is used only for the account store. lego's API takes no context, so
// cancelling ctx does not interrupt a running ACME exchange; the timeouts
// described at the top of this file bound it instead. The programs of exec
// DNS providers end with the ctx of NewIssuer, not this one. certfolds waits for
// the scheduler's in-flight Issue during shutdown for a bounded time only
// (server.Run), and abandons it past that.
func (i *Issuer) Issue(ctx context.Context, cfg *config.ServerConfig, spec config.CertificateSpec, replacing []byte) (*Result, error) {
	caEntry, ok := cfg.ACME.CAs[spec.CA]
	if !ok {
		return nil, fmt.Errorf("unknown CA %q", spec.CA)
	}

	client, err := i.accountClient(ctx, cfg, spec, caEntry)
	if err != nil {
		return nil, err
	}

	// Configure DNS provider.
	dnsP, ok := cfg.DNSProviders[spec.DNSProvider]
	if !ok {
		return nil, fmt.Errorf("unknown DNS provider %q", spec.DNSProvider)
	}
	provider, err := buildDNSProvider(i.programs, dnsP)
	if err != nil {
		return nil, fmt.Errorf("dns provider %q: %w", spec.DNSProvider, err)
	}
	// Unlike the process-wide resolvers, skipping the propagation check is an
	// option of this challenge only, so each provider can choose.
	skipPropagation := dns01.CondOption(dnsP.SkipPropagationCheck, dns01.PropagationWait(0, true))
	if err := client.Challenge.SetDNS01Provider(provider, skipPropagation); err != nil {
		return nil, fmt.Errorf("set dns01 provider: %w", err)
	}

	req := certificate.ObtainRequest{
		Domains: spec.Domains,
		Bundle:  true,
	}
	if id, ok := ariCertID(replacing); ok {
		req.ReplacesCertID = id
	}
	res, err := client.Certificate.Obtain(req)
	if err != nil {
		return nil, fmt.Errorf("obtain certificate: %w", err)
	}
	return newResult(res, spec.Domains)
}

// newResult returns what the CA issued, once it is checked against the order
// for domains: lego checks neither that the leaf certificate is for the
// private key it generated nor that it names the ordered domains, and the
// clients install the two as a pair.
func newResult(res *certificate.Resource, domains []string) (*Result, error) {
	leaf, err := certcrypto.ParsePEMCertificate(res.Certificate)
	if err != nil {
		return nil, fmt.Errorf("issued certificate: %w", err)
	}
	key, err := certcrypto.ParsePEMPrivateKey(res.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("issued private key: %w", err)
	}
	// The public keys of every key type lego parses have Equal.
	signer, ok := key.(crypto.Signer)
	if !ok || !signer.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(leaf.PublicKey) {
		return nil, errors.New("issued certificate is not for the private key of the order")
	}
	for _, domain := range domains {
		if !slices.ContainsFunc(leaf.DNSNames, func(name string) bool { return strings.EqualFold(name, domain) }) {
			return nil, fmt.Errorf("issued certificate does not name %s", domain)
		}
	}
	return &Result{
		Domain:      res.Domain,
		Certificate: res.Certificate,
		PrivateKey:  res.PrivateKey,
		IssuerCert:  res.IssuerCertificate,
		NotAfter:    leaf.NotAfter,
	}, nil
}

// ---------------------------------------------------------------------------
// Account management
// ---------------------------------------------------------------------------

// accountClient returns a lego client acting for the ACME account of spec's
// CA, registering the account first when the store has none for the CA's
// directory, and sending the CA the configured email address when it changed.
//
// An account belongs to the directory it was registered with, so a new
// directory gets a new key. The key is stored with its registration, once the
// CA has registered it: an account the CA refuses never replaces the stored
// one. A new email address keeps the account and its key, and only updates the
// account's contact: a new key would need a new registration, which a CA that
// binds accounts to a one-time external account binding refuses.
//
// Everything from reading the stored account to storing the registration runs
// under the lock of spec's CA. Without it, two first issuances for one CA
// could each create a key, and the stored record could end up pairing one key
// with the other's registration, which the CA rejects on every later request.
// The lock is released before the caller orders the certificate, so
// issuances still run in parallel.
//
// There is one lock per CA so that a stalled CA delays only its own
// issuances: every issuance holds its CA's lock while lego fetches the
// directory, for up to lego's request timeouts. The lock is keyed by CA name,
// the key of the account record in the store. A change of the CA's directory
// replaces that same record, so keying by directory would let an issuance
// started before a reload and one started after it write the record at once.
//
// An error of the store is returned without registering or writing anything:
// it may be transient and says nothing about the record, and taking it for a
// missing account would throw away a working one and register another.
func (i *Issuer) accountClient(ctx context.Context, cfg *config.ServerConfig, spec config.CertificateSpec, caEntry config.CAEntry) (*lego.Client, error) {
	lock, _ := i.accountLocks.LoadOrStore(spec.CA, new(sync.Mutex))
	mu := lock.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	rec, err := i.accounts.Get(ctx, spec.CA, nil)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		rec = &store.AccountRecord{}
	case err != nil:
		return nil, fmt.Errorf("account: %w", err)
	}
	var key *ecdsa.PrivateKey
	if rec.Directory == caEntry.Directory && rec.KeyPEM != "" {
		if key, err = parseECDSAKey([]byte(rec.KeyPEM)); err != nil {
			return nil, fmt.Errorf("account key: %w", err)
		}
	} else {
		if key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			return nil, fmt.Errorf("account key: %w", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("account key: %w", err)
		}
		rec = &store.AccountRecord{
			CA:        spec.CA,
			Directory: caEntry.Directory,
			KeyPEM:    string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		}
	}

	u := &legoUser{
		email: cfg.ACME.Email,
		key:   key,
		reg:   storedRegistration(rec),
	}

	legoCfg := lego.NewConfig(u)
	legoCfg.CADirURL = caEntry.Directory
	legoCfg.Certificate.KeyType = specKeyType(spec.KeyType)

	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return nil, fmt.Errorf("lego client: %w", err)
	}

	switch {
	case u.reg == nil:
		if u.reg, err = register(client, caEntry); err != nil {
			return nil, fmt.Errorf("register: %w", err)
		}
	case rec.Email != cfg.ACME.Email:
		// The contact is the only field sent: RFC 8555 lets a client not
		// update its agreement to the terms of service, and lego leaves
		// the field out when it is false.
		if u.reg, err = client.Registration.UpdateRegistration(registration.RegisterOptions{}); err != nil {
			return nil, fmt.Errorf("update account contact: %w", err)
		}
	default:
		return client, nil
	}
	regJSON, err := json.Marshal(u.reg)
	if err != nil {
		return nil, err
	}
	rec.Email = cfg.ACME.Email
	rec.RegistrationJSON = string(regJSON)
	// The CA holds the account now, whether or not the caller is still
	// there: lego does not stop for ctx, and a key that is not stored is lost.
	if err := i.accounts.Upsert(context.WithoutCancel(ctx), rec, nil); err != nil {
		return nil, fmt.Errorf("store account: %w", err)
	}
	return client, nil
}

// storedRegistration returns the registration stored in rec, or nil when it
// has none.
//
// A stored registration that does not parse counts as none. Such a record is
// damaged and stays so, and registering the stored key again repairs it
// without replacing the account: a CA answers a key it knows with the
// existing account (RFC 8555, section 7.3).
func storedRegistration(rec *store.AccountRecord) *registration.Resource {
	if rec.RegistrationJSON == "" {
		return nil
	}
	var reg registration.Resource
	if json.Unmarshal([]byte(rec.RegistrationJSON), &reg) != nil {
		return nil // damaged: register the key again, see above
	}
	return &reg
}

// register registers the account key of client with the CA, bound to the
// CA's external account when it has one, and returns the registration.
func register(client *lego.Client, caEntry config.CAEntry) (*registration.Resource, error) {
	if caEntry.EABKID != "" {
		return client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
			TermsOfServiceAgreed: true,
			Kid:                  caEntry.EABKID,
			HmacEncoded:          caEntry.EABHMAC,
		})
	}
	return client.Registration.Register(registration.RegisterOptions{
		TermsOfServiceAgreed: true,
	})
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

// buildDNSProvider builds the provider p configures. The programs of an exec
// provider are killed when ctx ends, and the gcloud provider fetches its
// access tokens with ctx.
func buildDNSProvider(ctx context.Context, p config.DNSProvider) (challenge.Provider, error) {
	cfg := p.Config
	var (
		provider challenge.ProviderTimeout
		err      error
		// secrets are the provider's credentials; see redactingProvider.
		secrets []string
	)
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
		secrets = []string{c.AuthToken, c.ZoneToken, c.AuthKey}
		provider, err = cloudflare.NewDNSProviderConfig(c)

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
		secrets = []string{c.APIKey, c.SecretKey}
		provider, err = alidns.NewDNSProviderConfig(c)

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
		secrets = []string{c.SecretID, c.SecretKey}
		provider, err = tencentcloud.NewDNSProviderConfig(c)

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
		secrets = []string{c.AccessKeyID, c.SecretAccessKey}
		if c.AccessKeyID == "" {
			// Without keys in the config, the AWS SDK may take them from
			// the environment, where they can be swapped as well.
			secrets = []string{os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"), os.Getenv("AWS_SESSION_TOKEN")}
		}
		provider, err = route53.NewDNSProviderConfig(c)

	case "gcloud":
		c := gcloud.NewDefaultConfig()
		c.PropagationTimeout, c.PollingInterval = dnsPropagationTimeout, dnsPollingInterval
		if c.ImpersonateServiceAccount != "" {
			// lego reads it from GCE_IMPERSONATE_SERVICE_ACCOUNT; ignoring it
			// would issue as a broader identity than intended.
			return nil, errors.New("gcloud: GCE_IMPERSONATE_SERVICE_ACCOUNT is not supported")
		}
		file, _ := cfg["service_account_file"].(string)
		var fileProject string
		if c.HTTPClient, fileProject, err = gcloudClient(ctx, file); err != nil {
			return nil, fmt.Errorf("gcloud: %w", err)
		}
		// A configured project overrides the service account's, as
		// GCE_PROJECT does in lego: the account may manage the zones of
		// another project.
		if c.Project, _ = cfg["project"].(string); c.Project == "" {
			c.Project = fileProject
		}
		if c.Project == "" {
			return nil, errors.New("gcloud: project missing: set project, or use a service account file with a project_id")
		}
		provider, err = gcloud.NewDNSProviderConfig(c)

	case "exec":
		return &execProvider{ctx: ctx, argv: p.Command}, nil

	default:
		return nil, fmt.Errorf("unsupported provider type %q", p.Type)
	}
	if err != nil {
		return nil, err
	}
	return newRedactingProvider(provider, secrets), nil
}

// gcloudClient returns the HTTP client of the gcloud provider, authorized for
// Cloud DNS by the service account key in file or, when file is empty, by
// application default credentials, and the project of the key file.
//
// lego's own constructors would build the client with no timeout and take
// the project from the key file over the configured one.
func gcloudClient(ctx context.Context, file string) (*http.Client, string, error) {
	// oauth2 fetches tokens with the client in ctx, and gives the client it
	// returns the same timeout.
	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Timeout: dnsAPITimeout})
	if file == "" {
		ts, err := google.DefaultTokenSource(ctx, gdns.NdevClouddnsReadwriteScope)
		if err != nil {
			return nil, "", err
		}
		return oauth2.NewClient(ctx, ts), "", nil
	}
	key, err := os.ReadFile(file)
	if err != nil {
		return nil, "", err
	}
	jwt, err := google.JWTConfigFromJSON(key, gdns.NdevClouddnsReadwriteScope)
	if err != nil {
		return nil, "", err
	}
	var account struct {
		ProjectID string `json:"project_id"`
	}
	if err := json.Unmarshal(key, &account); err != nil {
		return nil, "", err
	}
	return oauth2.NewClient(ctx, jwt.TokenSource(ctx)), account.ProjectID, nil
}

// redactingProvider is a built-in provider whose Present and CleanUp errors
// have its credentials replaced with REDACTED, before lego, the certificate's
// last error, IPC or events see them. A provider's API may quote a credential
// sent in the wrong field: AWS answers a secret key given as the access key ID
// with an error that repeats it. Key IDs are replaced too, since they hold the
// secret when the two are swapped. Only exact copies are replaced. Errors a
// provider logs itself instead of returning them (lego's cloudflare provider
// logs a failed record deletion in CleanUp) reach the events unredacted.
//
// It keeps the provider's Timeout, so lego still waits for Certfold's bounds.
// lego's other optional provider interface, Sequential, is implemented by
// none of the built-in providers.
type redactingProvider struct {
	challenge.ProviderTimeout
	secrets *strings.Replacer
}

func newRedactingProvider(p challenge.ProviderTimeout, secrets []string) *redactingProvider {
	// An empty value would match everywhere, and of two values where one
	// starts the other, the longer must be tried first.
	secrets = slices.DeleteFunc(slices.Clone(secrets), func(s string) bool { return s == "" })
	slices.SortFunc(secrets, func(a, b string) int { return len(b) - len(a) })
	var oldnew []string
	for _, s := range secrets {
		oldnew = append(oldnew, s, "REDACTED")
	}
	return &redactingProvider{ProviderTimeout: p, secrets: strings.NewReplacer(oldnew...)}
}

func (p *redactingProvider) Present(domain, token, keyAuth string) error {
	return p.redact(p.ProviderTimeout.Present(domain, token, keyAuth))
}

func (p *redactingProvider) CleanUp(domain, token, keyAuth string) error {
	return p.redact(p.ProviderTimeout.CleanUp(domain, token, keyAuth))
}

// redact returns a new error, not one wrapping err, so that unwrapping cannot
// reach the credentials either.
func (p *redactingProvider) redact(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(p.secrets.Replace(err.Error()))
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
