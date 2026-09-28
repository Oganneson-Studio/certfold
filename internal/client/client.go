package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/rand"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/enroll"
	"github.com/Oganneson-Studio/sigil/internal/output"
	"github.com/Oganneson-Studio/sigil/pkg/proto"
)

const jitterPct = 0.1 // ±10 % of the backoff after a failed round

// httpTimeout bounds each request of the HTTP client built from the identity.
// The loop's GET /v1/sync, which the server may hold for longer, does not use
// it. A variable only so tests can shorten it.
var httpTimeout = 30 * time.Second

// Client is the sigilc runtime.
type Client struct {
	// cfg and http change only while pullMu is held as well, so the holder of
	// pullMu reads them without cfgMu.
	cfgMu sync.RWMutex
	cfg   *config.ClientConfig
	http  *http.Client

	// pullMu serializes the apply phases of the sync loop, IPC fetches and
	// reloads: identity renewal, downloading bundles and writing the store,
	// reconciling outputs and running on_change programs. The loop does not
	// hold it while it waits for the answer to GET /v1/sync.
	pullMu sync.Mutex
	// store holds the content of certs.json: the material of every
	// certificate in the last view applied. Guarded by pullMu.
	store map[string]storedCert
	// storeUnsaved records that a write failed after a reconcile changed
	// hook_pending bits in memory, so certs.json lags behind them. Every
	// reconcile writes the store again until a write succeeds, and any write
	// that succeeds clears it. Guarded by pullMu.
	storeUnsaved bool
	// etag is the ETag of the last view applied in full, sent as
	// If-None-Match. Guarded by pullMu.
	etag string
	// syncCancel cancels the loop's GET /v1/sync in flight. The loop sets it
	// in the pullMu section where it takes the configuration, identity and
	// etag for the request, so Reload and an identity switch cancel every
	// request made with what they replace, and an IPC fetch every request
	// whose answer could be older than its own. Guarded by pullMu.
	syncCancel context.CancelFunc
	// runCtx is the ctx of Run from the start of Run on; on_change programs
	// run under it, or under context.Background before Run starts. It stays
	// set after Run returns, so a fetch or reload that takes pullMu after
	// that cancels its programs at once instead of leaving them to outlive
	// the daemon. Guarded by pullMu.
	runCtx   context.Context
	reloadCh chan struct{}

	statusMu sync.RWMutex
	status   RuntimeStatus

	identitySaver IdentitySaver
	now           func() time.Time
	// hook runs the on_change program of a certificate: runHook, or a
	// stand-in in tests.
	hook func(ctx context.Context, certName string, argv []string) error
}

// IdentitySaver persists a renewed mTLS identity before the running client
// switches to it.
type IdentitySaver func(caCert, clientCert, clientKey string) error

// Option customizes a Client.
type Option func(*Client)

// WithIdentitySaver enables automatic identity renewal persistence.
func WithIdentitySaver(saver IdentitySaver) Option {
	return func(c *Client) { c.identitySaver = saver }
}

// RuntimeStatus is a point-in-time snapshot of the sigilc daemon.
type RuntimeStatus struct {
	Name      string
	ServerURL string
	// Online reports whether the last round of the loop, or IPC fetch, got a
	// 200 or 304 from GET /v1/sync, and LastPullAt when the last one did.
	Online     bool
	LastPullAt time.Time
	// LastError is the joined error of the last round, IPC fetch or reload,
	// or empty if it had none.
	LastError string
	// Certs lists the stored certificates in name order.
	Certs []CertStatus
}

// CertStatus describes a stored certificate. NotAfter is that of its first
// certificate. Outputs is the number of outputs client.yaml configures for
// it, and OnChange reports whether client.yaml configures an on_change
// program for it. HookPending is the stored hook_pending.
type CertStatus struct {
	Name, Fingerprint string
	NotAfter          time.Time
	Outputs           int
	OnChange          bool
	HookPending       bool
}

// New constructs a Client with an mTLS-capable HTTP client built from
// cfg.Identity, and reads the store in cfg.Client.DataDir.
func New(cfg *config.ClientConfig, options ...Option) (*Client, error) {
	httpClient, err := buildHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	certs, err := loadStore(cfg.Client.DataDir)
	if err != nil {
		return nil, fmt.Errorf("load certificate store: %w", err)
	}
	c := &Client{
		cfg:      cfg,
		http:     httpClient,
		store:    certs,
		reloadCh: make(chan struct{}, 1),
		status: RuntimeStatus{
			Name:      cfg.Client.Name,
			ServerURL: cfg.Client.ServerURL,
			Certs:     certStatuses(certs, cfg),
		},
		now:  time.Now,
		hook: runHook,
	}
	for _, option := range options {
		option(c)
	}
	return c, nil
}

// Run reconciles the outputs with the store, then runs the sync loop until
// ctx is cancelled.
func (c *Client) Run(ctx context.Context) error {
	// Restore the outputs before the first request: they come back even
	// while the server is unreachable.
	c.pullMu.Lock()
	c.runCtx = ctx
	c.recordReconcile(c.reconcileLocked())
	c.pullMu.Unlock()

	err := c.syncLoop(ctx)
	// An IPC fetch or reload may still be writing outputs or the store.
	// Take pullMu once so Run returns after it ends.
	c.pullMu.Lock()
	c.pullMu.Unlock()
	return err
}

// Fetch runs a full pull in the caller's goroutine. It asks GET /v1/sync for
// the view without If-None-Match, downloads the certificates whose
// fingerprints changed, and name as well when it is not empty, then
// reconciles every output with the store and runs the pending on_change
// programs. A failed step does not stop the later ones; Fetch returns their
// joined errors.
func (c *Client) Fetch(ctx context.Context, name string) error {
	c.pullMu.Lock()
	defer c.pullMu.Unlock()
	// The loop's request in flight may be answered with an older view than
	// the one this fetch gets. Applied after this fetch, that view would drop
	// the certificates added since, and download again the ones removed. Cancel
	// it; the loop starts over with the etag this fetch leaves.
	if c.syncCancel != nil {
		c.syncCancel()
	}

	var errs []error
	var answeredAt time.Time
	// As in the loop, a failed renewal does not stop the pull: the current
	// identity stays valid until it expires.
	if err := c.renewIdentityLocked(ctx); err != nil {
		errs = append(errs, fmt.Errorf("renew client identity: %w", err))
	}
	if result, err := requestSync(ctx, c.http, c.cfg.Client.ServerURL, ""); err != nil {
		errs = append(errs, fmt.Errorf("sync: %w", err))
	} else {
		answeredAt = time.Now()
		if result.modified {
			if name != "" && !slices.ContainsFunc(result.view, func(s proto.CertSummary) bool { return s.Name == name }) {
				errs = append(errs, fmt.Errorf("certificate %q is not subscribed", name))
			}
			if err := c.applyViewLocked(ctx, result, name); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if err := c.reconcileLocked(); err != nil {
		errs = append(errs, err)
	}
	err := errors.Join(errs...)
	c.recordPullLocked(answeredAt, err)
	return err
}

func (c *Client) renewIdentityLocked(ctx context.Context) error {
	c.cfgMu.RLock()
	cfgSnapshot := *c.cfg
	httpClient := c.http
	c.cfgMu.RUnlock()

	if cfgSnapshot.Identity.ClientCert == "" {
		return nil
	}
	block, _ := pem.Decode([]byte(cfgSnapshot.Identity.ClientCert))
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("parse current client certificate PEM")
	}
	currentCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse current client certificate: %w", err)
	}
	renewBefore := cfgSnapshot.Client.IdentityRenewBefore
	if renewBefore == 0 {
		renewBefore = config.DefaultIdentityRenewBefore
	}
	if c.now().Add(renewBefore).Before(currentCert.NotAfter) {
		return nil
	}
	if c.identitySaver == nil {
		return fmt.Errorf("identity expires at %s but no identity saver is configured", currentCert.NotAfter.UTC().Format(time.RFC3339))
	}

	keyAndCSR, err := enroll.GenerateKeyAndCSR(cfgSnapshot.Client.Name)
	if err != nil {
		return err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: keyAndCSR.CSRDER})
	body, err := json.Marshal(proto.RenewIdentityRequest{CSR: string(csrPEM)})
	if err != nil {
		return fmt.Errorf("encode renewal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		cfgSnapshot.Client.ServerURL+"/v1/identity/renew", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request renewal: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("renewal server returned %d", resp.StatusCode)
	}
	var renewal proto.RenewIdentityResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&renewal); err != nil {
		return fmt.Errorf("decode renewal response: %w", err)
	}
	updated := cfgSnapshot
	updated.Identity.ClientCert = renewal.ClientCert
	updated.Identity.ClientKey = string(keyAndCSR.KeyPEM)
	newHTTPClient, err := validateRenewedIdentity(&updated, c.now())
	if err != nil {
		return err
	}
	if err := c.identitySaver(
		updated.Identity.CACert, updated.Identity.ClientCert, updated.Identity.ClientKey,
	); err != nil {
		return fmt.Errorf("persist renewed identity: %w", err)
	}

	c.cfgMu.Lock()
	c.cfg = &updated
	c.http = newHTTPClient
	c.cfgMu.Unlock()
	// The loop's request in flight still presents the old identity. Cancel
	// it so the next round waits with the new one. The etag stays: the view
	// does not depend on the identity.
	if c.syncCancel != nil {
		c.syncCancel()
	}
	return nil
}

func validateRenewedIdentity(cfg *config.ClientConfig, now time.Time) (*http.Client, error) {
	client, err := buildHTTPClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("validate renewed key pair: %w", err)
	}
	block, _ := pem.Decode([]byte(cfg.Identity.ClientCert))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("renewal response does not contain a client certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse renewed certificate: %w", err)
	}
	if leaf.Subject.CommonName != cfg.Client.Name {
		return nil, fmt.Errorf("renewed certificate name %q does not match client %q", leaf.Subject.CommonName, cfg.Client.Name)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(cfg.Identity.CACert)) {
		return nil, fmt.Errorf("parse identity CA certificate")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, fmt.Errorf("verify renewed certificate: %w", err)
	}
	return client, nil
}

// getBundle calls GET /v1/certificates/{name}/bundle.
func (c *Client) getBundle(ctx context.Context, name string) (*proto.CertBundle, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.cfg.Client.ServerURL+"/v1/certificates/"+url.PathEscape(name)+"/bundle", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d", resp.StatusCode)
	}
	var b proto.CertBundle
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return &b, nil
}

// reconcileLocked brings the outputs of every stored certificate in line with
// its material, then runs the pending on_change programs in name order, and
// returns the joined errors of both.
//
// When Reconcile rewrites the content of an output of a certificate that has
// an on_change program, the certificate gets hook_pending; repairing only the
// mode or owner of an output does not set it. The new bits are written to the
// store before any program runs. A program does not run while its
// certificate's outputs failed to reconcile, since they may be incomplete. A
// program that exits 0 clears the bit, and so does the lack of a program; a
// failure keeps it, so the program runs again after the next reconcile. The
// cleared bits are written once all programs have run.
func (c *Client) reconcileLocked() error {
	certificates := c.cfg.Certificates
	names := slices.Sorted(maps.Keys(c.store))
	var errs []error
	failed := make(map[string]bool)
	pending := false
	for _, name := range names {
		outputs := certificates[name].Outputs
		if len(outputs) == 0 {
			continue
		}
		cert := c.store[name]
		changed, err := output.Reconcile(splitBundle(cert), outputs)
		if err != nil {
			errs = append(errs, fmt.Errorf("outputs of certificate %s: %w", name, err))
			failed[name] = true
		}
		if changed && len(certificates[name].OnChange) > 0 && !cert.HookPending {
			cert.HookPending = true
			c.store[name] = cert
			pending = true
		}
	}
	if pending || c.storeUnsaved {
		if err := c.writeStoreLocked(); err != nil {
			errs = append(errs, err)
		}
	}

	ctx := c.runCtx
	if ctx == nil {
		ctx = context.Background()
	}
	cleared := false
	for _, name := range names {
		cert := c.store[name]
		if !cert.HookPending {
			continue
		}
		if argv := certificates[name].OnChange; len(argv) > 0 {
			if failed[name] {
				continue
			}
			if err := c.hook(ctx, name, argv); err != nil {
				errs = append(errs, err)
				continue
			}
		}
		cert.HookPending = false
		c.store[name] = cert
		cleared = true
	}
	if cleared {
		if err := c.writeStoreLocked(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// writeStoreLocked writes the store in memory to certs.json, and records
// whether certs.json lags behind it.
func (c *Client) writeStoreLocked() error {
	err := saveStore(c.cfg.Client.DataDir, c.store)
	c.storeUnsaved = err != nil
	if err != nil {
		return fmt.Errorf("save store: %w", err)
	}
	return nil
}

// Status returns a copy of the current runtime status.
func (c *Client) Status() RuntimeStatus {
	c.cfgMu.RLock()
	name := c.cfg.Client.Name
	serverURL := c.cfg.Client.ServerURL
	c.cfgMu.RUnlock()

	c.statusMu.RLock()
	defer c.statusMu.RUnlock()
	status := c.status
	status.Name = name
	status.ServerURL = serverURL
	status.Certs = slices.Clone(c.status.Certs)
	return status
}

// Reload applies a newly parsed client configuration. Changing the IPC socket
// or the data directory requires a service restart: the command process owns
// the IPC listener, and New read the store from the data directory.
//
// Before it returns, Reload reconciles the outputs with the store under the
// new configuration and runs the pending on_change programs. Their errors go
// to the status rather than to the caller, since the configuration is applied
// by then. Reload then clears the etag, cancels the loop's request in flight,
// which was made with the old configuration, and wakes the loop from a
// backoff, so the loop pulls the whole view at once.
func (c *Client) Reload(cfg *config.ClientConfig) error {
	httpClient, err := buildHTTPClient(cfg)
	if err != nil {
		return err
	}

	c.pullMu.Lock()
	defer c.pullMu.Unlock()
	c.cfgMu.Lock()
	if cfg.Client.IPCSocket != c.cfg.Client.IPCSocket {
		c.cfgMu.Unlock()
		return fmt.Errorf("client.ipc_socket changed; restart sigilc to apply it")
	}
	if cfg.Client.DataDir != c.cfg.Client.DataDir {
		c.cfgMu.Unlock()
		return fmt.Errorf("client.data_dir changed; restart sigilc to apply it")
	}
	c.cfg = cfg
	c.http = httpClient
	c.cfgMu.Unlock()

	c.statusMu.Lock()
	c.status.Name = cfg.Client.Name
	c.status.ServerURL = cfg.Client.ServerURL
	c.statusMu.Unlock()

	c.recordReconcile(c.reconcileLocked())
	c.etag = ""
	if c.syncCancel != nil {
		c.syncCancel()
	}
	select {
	case c.reloadCh <- struct{}{}:
	default:
	}
	return nil
}

// recordPullLocked records the outcome of a round of the loop or an IPC
// fetch. answeredAt is when GET /v1/sync answered 200 or 304, or zero if it
// did not.
func (c *Client) recordPullLocked(answeredAt time.Time, err error) {
	certs := certStatuses(c.store, c.cfg)
	c.statusMu.Lock()
	defer c.statusMu.Unlock()
	c.status.Online = !answeredAt.IsZero()
	if c.status.Online {
		c.status.LastPullAt = answeredAt.UTC()
	}
	c.status.Certs = certs
	c.setLastErrorLocked(err)
}

// recordReconcile records the outcome of a reconcile without a request, at
// startup or on reload, and describes the certificates under the running
// configuration, so the status follows a reload at once. The next round
// overwrites it. The caller holds pullMu.
func (c *Client) recordReconcile(err error) {
	certs := certStatuses(c.store, c.cfg)
	c.statusMu.Lock()
	defer c.statusMu.Unlock()
	c.status.Certs = certs
	c.setLastErrorLocked(err)
}

// setLastErrorLocked sets LastError; statusMu must be held.
func (c *Client) setLastErrorLocked(err error) {
	if err == nil {
		c.status.LastError = ""
	} else {
		c.status.LastError = err.Error()
	}
}

// certStatuses describes the certificates in certs, in name order, with the
// outputs and on_change program cfg configures for them.
func certStatuses(certs map[string]storedCert, cfg *config.ClientConfig) []CertStatus {
	out := make([]CertStatus, 0, len(certs))
	for _, name := range slices.Sorted(maps.Keys(certs)) {
		cert := certs[name]
		configured := cfg.Certificates[name]
		out = append(out, CertStatus{
			Name:        name,
			Fingerprint: cert.Fingerprint,
			NotAfter:    leafNotAfter(cert.FullchainPEM),
			Outputs:     len(configured.Outputs),
			OnChange:    len(configured.OnChange) > 0,
			HookPending: cert.HookPending,
		})
	}
	return out
}

// leafNotAfter returns the NotAfter of the first certificate in
// fullchainPEM, or the zero time if it cannot be parsed.
func leafNotAfter(fullchainPEM string) time.Time {
	block, _ := pem.Decode([]byte(fullchainPEM))
	if block == nil {
		return time.Time{}
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}
	}
	return leaf.NotAfter
}

// splitBundle splits the stored fullchain (cert + intermediates) into CertPEM
// and ChainPEM. It treats the first PEM block as the leaf cert and the rest as
// the chain.
func splitBundle(cert storedCert) *output.CertBundle {
	full := []byte(cert.FullchainPEM)
	block, rest := pem.Decode(full)
	certPEM := full
	if block != nil {
		certPEM = pem.EncodeToMemory(block)
	}
	return &output.CertBundle{
		CertPEM:  certPEM,
		ChainPEM: rest,
		KeyPEM:   []byte(cert.KeyPEM),
	}
}

// buildHTTPClient constructs an mTLS HTTP client from cfg.Identity. The server
// is authenticated with the same roots as during enrollment, so a server that
// presents a publicly trusted server.tls_cert_file stays reachable.
func buildHTTPClient(cfg *config.ClientConfig) (*http.Client, error) {
	id := cfg.Identity
	if id.ClientCert == "" && id.ClientKey == "" {
		// No identity yet (pre-enroll): plain HTTP client (no mTLS).
		return &http.Client{Timeout: httpTimeout}, nil
	}
	tlsCert, err := tls.X509KeyPair([]byte(id.ClientCert), []byte(id.ClientKey))
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}
	pool, err := enroll.ServerRoots(id.CACert)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}
	return &http.Client{
		Timeout: httpTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}, nil
}

// jitter returns d ± pct*d (uniform random).
func jitter(d time.Duration, pct float64) time.Duration {
	window := float64(d) * pct
	offset := (2*rand.Float64() - 1) * window
	return d + time.Duration(offset)
}
