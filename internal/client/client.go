// Package client implements the sigilc runtime: pull loop, push receiver,
// certificate caching, and output writing.
package client

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/enroll"
	"github.com/Oganneson-Studio/sigil/internal/output"
	"github.com/Oganneson-Studio/sigil/internal/securefile"
	"github.com/Oganneson-Studio/sigil/internal/version"
	"github.com/Oganneson-Studio/sigil/pkg/proto"
)

const jitterPct = 0.1 // ±10 % of pull_interval

// state tracks the fingerprints of certs written to disk.
type state struct {
	Certs map[string]string `json:"certs"` // name → fingerprint
}

// Client is the sigilc runtime.
type Client struct {
	cfgMu sync.RWMutex
	cfg   *config.ClientConfig
	http  *http.Client

	pullMu sync.Mutex
	// rewriteAll makes the next full pull rewrite the outputs of every
	// subscribed certificate, whatever the fingerprints in state.json say:
	// outputs may have been added to client.yaml or removed from disk since
	// they were last written. New and Reload set it; a full pull clears it
	// once it has listed the subscribed certificates. If that pull fails for a
	// certificate whose recorded fingerprint equals the served one, its entry
	// is dropped from state.json so the next pull retries it; an older
	// fingerprint stays, since a diff retries the certificate anyway.
	// Guarded by pullMu.
	rewriteAll bool
	reloadCh   chan struct{}

	statusMu sync.RWMutex
	status   RuntimeStatus

	pushInFlight atomic.Bool

	identitySaver IdentitySaver
	now           func() time.Time
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
	Name       string
	ServerURL  string
	Online     bool
	LastPullAt time.Time
	LastError  string
	Certs      map[string]string
}

// New constructs a Client with an mTLS-capable HTTP client built from cfg.Identity.
func New(cfg *config.ClientConfig, options ...Option) (*Client, error) {
	if err := config.ValidatePushListen(cfg.Client.PushListen); err != nil {
		return nil, fmt.Errorf("client.push_listen: %w", err)
	}
	httpClient, err := buildHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	c := &Client{
		cfg:        cfg,
		http:       httpClient,
		rewriteAll: true,
		reloadCh:   make(chan struct{}, 1),
		status: RuntimeStatus{
			Name:      cfg.Client.Name,
			ServerURL: cfg.Client.ServerURL,
			Certs:     map[string]string{},
		},
		now: time.Now,
	}
	for _, option := range options {
		option(c)
	}
	c.status.Certs = cloneFingerprints(c.loadState().Certs)
	return c, nil
}

// Run starts the pull loop (and optional push receiver) and blocks until ctx
// is cancelled.
func (c *Client) Run(ctx context.Context) error {
	pushListen := c.pushListen()
	if err := config.ValidatePushListen(pushListen); err != nil {
		return fmt.Errorf("client.push_listen: %w", err)
	}

	// First pull immediately. New set rewriteAll, so it rewrites every output.
	_ = c.pullOnce(ctx)

	// Push receiver (optional).
	if pushListen != "" {
		go c.startPushReceiver(ctx, pushListen)
	}

	err := c.pullLoop(ctx)
	// A push or IPC pull runs outside the loop and may still be writing
	// outputs or state.json. Take pullMu once so Run returns after it ends.
	c.pullMu.Lock()
	c.pullMu.Unlock()
	return err
}

// pullLoop ticks every pull_interval ±10 % and calls pullOnce. A successful
// Reload triggers an immediate pull and restarts the interval.
func (c *Client) pullLoop(ctx context.Context) error {
	for {
		interval := jitter(c.pullInterval(), jitterPct)
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-c.reloadCh:
			timer.Stop()
			_ = c.pullOnce(ctx)
		case <-timer.C:
			_ = c.pullOnce(ctx)
		}
	}
}

// pullOnce executes one full pull cycle:
//  1. GET /v1/certificates
//  2. Diff against local state, or select every certificate while
//     rewriteAll is set
//  3. Fetch selected bundles + write outputs
//  4. Persist updated state
//  5. POST /v1/heartbeat
func (c *Client) pullOnce(ctx context.Context) error {
	return c.Fetch(ctx, "")
}

// Fetch performs an immediate pull. When name is non-empty, that certificate
// is fetched even when its fingerprint has not changed. An empty name fetches
// the certificates whose fingerprints changed, or every subscribed
// certificate after startup or a reload.
func (c *Client) Fetch(ctx context.Context, name string) error {
	c.pullMu.Lock()
	defer c.pullMu.Unlock()
	if err := c.renewIdentityLocked(ctx); err != nil {
		err = fmt.Errorf("renew client identity: %w", err)
		c.recordPull(err)
		return err
	}
	c.cfgMu.RLock()
	defer c.cfgMu.RUnlock()

	err := c.fetchLocked(ctx, name)
	c.recordPull(err)
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

func (c *Client) fetchLocked(ctx context.Context, name string) error {
	summaries, err := c.listCerts(ctx)
	if err != nil {
		return fmt.Errorf("list certs: %w", err)
	}

	st := c.loadState()
	changed := diffCerts(summaries, st.Certs)
	if name != "" {
		changed = nil
		for _, summary := range summaries {
			if summary.Name == name {
				changed = append(changed, summary)
				break
			}
		}
		if len(changed) == 0 {
			return fmt.Errorf("certificate %q is not subscribed", name)
		}
	} else if c.rewriteAll {
		changed = summaries
		c.rewriteAll = false
	}

	var errs []error
	for _, s := range changed {
		bundle, err := c.getBundle(ctx, s.Name)
		if err == nil {
			if err = c.writeOutputs(s.Name, bundle); err != nil {
				err = fmt.Errorf("write %s: %w", s.Name, err)
			}
		}
		if err != nil {
			errs = append(errs, err)
			// A diff skips a certificate whose fingerprint state.json already
			// records, so a forced or named pull that failed for it would not
			// be retried. Forget the fingerprint so the next pull retries it.
			if st.Certs[s.Name] == s.Fingerprint {
				delete(st.Certs, s.Name)
			}
			continue
		}
		st.Certs[s.Name] = s.Fingerprint
	}

	if err := c.saveState(st); err != nil {
		errs = append(errs, fmt.Errorf("save state: %w", err))
	}
	if err := c.heartbeat(ctx, st); err != nil {
		errs = append(errs, fmt.Errorf("heartbeat: %w", err))
	}
	c.statusMu.Lock()
	c.status.Certs = cloneFingerprints(st.Certs)
	c.statusMu.Unlock()
	return errors.Join(errs...)
}

// listCerts calls GET /v1/certificates and returns the response.
func (c *Client) listCerts(ctx context.Context) ([]proto.CertSummary, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.cfg.Client.ServerURL+"/v1/certificates", nil)
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
	var out []proto.CertSummary
	return out, json.NewDecoder(resp.Body).Decode(&out)
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
		return nil, fmt.Errorf("bundle %s: server returned %d", name, resp.StatusCode)
	}
	var b proto.CertBundle
	return &b, json.NewDecoder(resp.Body).Decode(&b)
}

// heartbeat calls POST /v1/heartbeat with the current fingerprint set.
func (c *Client) heartbeat(ctx context.Context, st *state) error {
	fp := ""
	for _, v := range st.Certs {
		fp = v
		break
	}
	body, _ := json.Marshal(proto.HeartbeatRequest{
		Version:     version.Version,
		Fingerprint: fp,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.Client.ServerURL+"/v1/heartbeat", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}

// writeOutputs renders the bundle into each configured output for certName.
func (c *Client) writeOutputs(certName string, bundle *proto.CertBundle) error {
	specs, ok := c.cfg.Outputs[certName]
	if !ok || len(specs) == 0 {
		// Cache to data_dir/cache/ even if no output specs.
		return c.cacheBundle(certName, bundle)
	}
	// Split fullchain into cert + chain.
	cb := splitBundle(bundle)
	for _, spec := range specs {
		if err := output.Write(cb, spec); err != nil {
			return err
		}
	}
	return nil
}

// cacheBundle writes the bundle to data_dir/cache/<name>/ as raw PEM files.
func (c *Client) cacheBundle(name string, bundle *proto.CertBundle) error {
	dir := filepath.Join(c.cfg.Client.DataDir, "cache", name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "fullchain.pem"), []byte(bundle.FullchainPEM), 0o644); err != nil {
		return err
	}
	return securefile.WriteFile(filepath.Join(dir, "key.pem"), []byte(bundle.KeyPEM))
}

// startPushReceiver starts a minimal HTTP server on push_listen that triggers
// pullOnce when it receives POST /v1/push/notify.
func (c *Client) startPushReceiver(ctx context.Context, listenAddr string) {
	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           c.pushHandler(ctx),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	_ = srv.ListenAndServe()
}

func (c *Client) pushHandler(ctx context.Context) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/push/notify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !validPushAuthorization(r.Header.Get("Authorization"), c.pushToken()) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		var notification proto.PushNotify
		if err := json.NewDecoder(r.Body).Decode(&notification); err != nil && err != io.EOF {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if !c.pushInFlight.CompareAndSwap(false, true) {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		go func(name string) {
			defer c.pushInFlight.Store(false)
			pullCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			_ = c.Fetch(pullCtx, name)
		}(notification.CertName)
		w.WriteHeader(http.StatusAccepted)
	})
	return mux
}

func validPushAuthorization(header, expected string) bool {
	const prefix = "Bearer "
	if expected == "" || !strings.HasPrefix(header, prefix) {
		return false
	}
	provided := strings.TrimPrefix(header, prefix)
	if len(provided) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

// loadState reads data_dir/state.json; returns an empty state on any error.
func (c *Client) loadState() *state {
	st := &state{Certs: make(map[string]string)}
	data, err := os.ReadFile(c.statePath())
	if err != nil {
		return st
	}
	_ = json.Unmarshal(data, st)
	if st.Certs == nil {
		st.Certs = make(map[string]string)
	}
	return st
}

func (c *Client) saveState(st *state) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.cfg.Client.DataDir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(c.statePath(), data, 0o600)
}

func (c *Client) statePath() string {
	return filepath.Join(c.cfg.Client.DataDir, "state.json")
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
	status.Certs = cloneFingerprints(c.status.Certs)
	return status
}

// Reload applies a newly parsed client configuration. Changing the IPC or
// push listener requires a service restart because those listeners are owned
// by Run and the command process respectively. Once applied, Run pulls
// immediately and rewrites the outputs of every subscribed certificate, so
// outputs added to client.yaml are written without waiting for a renewal.
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
	if cfg.Client.PushListen != c.cfg.Client.PushListen {
		c.cfgMu.Unlock()
		return fmt.Errorf("client.push_listen changed; restart sigilc to apply it")
	}
	c.cfg = cfg
	c.http = httpClient
	c.cfgMu.Unlock()
	c.rewriteAll = true

	c.statusMu.Lock()
	c.status.Name = cfg.Client.Name
	c.status.ServerURL = cfg.Client.ServerURL
	c.statusMu.Unlock()
	select {
	case c.reloadCh <- struct{}{}:
	default:
	}
	return nil
}

func (c *Client) recordPull(err error) {
	c.statusMu.Lock()
	defer c.statusMu.Unlock()
	c.status.LastPullAt = time.Now().UTC()
	c.status.Online = err == nil
	if err == nil {
		c.status.LastError = ""
	} else {
		c.status.LastError = err.Error()
	}
}

func (c *Client) pullInterval() time.Duration {
	c.cfgMu.RLock()
	defer c.cfgMu.RUnlock()
	return c.cfg.Client.PullInterval
}

func (c *Client) pushListen() string {
	c.cfgMu.RLock()
	defer c.cfgMu.RUnlock()
	return c.cfg.Client.PushListen
}

func (c *Client) pushToken() string {
	c.cfgMu.RLock()
	defer c.cfgMu.RUnlock()
	return c.cfg.Client.PushToken
}

func cloneFingerprints(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for name, fingerprint := range src {
		dst[name] = fingerprint
	}
	return dst
}

// diffCerts returns the summaries whose fingerprints differ from localState.
func diffCerts(summaries []proto.CertSummary, localState map[string]string) []proto.CertSummary {
	var changed []proto.CertSummary
	for _, s := range summaries {
		if localState[s.Name] != s.Fingerprint {
			changed = append(changed, s)
		}
	}
	return changed
}

// splitBundle splits a FullchainPEM (cert + intermediates) into CertPEM and ChainPEM.
// It treats the first PEM block as the leaf cert and the rest as the chain.
func splitBundle(b *proto.CertBundle) *output.CertBundle {
	full := []byte(b.FullchainPEM)
	block, rest := pem.Decode(full)
	certPEM := full
	if block != nil {
		certPEM = pem.EncodeToMemory(block)
	}
	return &output.CertBundle{
		CertPEM:  certPEM,
		ChainPEM: rest,
		KeyPEM:   []byte(b.KeyPEM),
	}
}

// buildHTTPClient constructs an mTLS HTTP client from cfg.Identity. The server
// is authenticated with the same roots as during enrollment, so a server that
// presents a publicly trusted server.tls_cert_file stays reachable.
func buildHTTPClient(cfg *config.ClientConfig) (*http.Client, error) {
	id := cfg.Identity
	if id.ClientCert == "" && id.ClientKey == "" {
		// No identity yet (pre-enroll): plain HTTP client (no mTLS).
		return &http.Client{Timeout: 30 * time.Second}, nil
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
		Timeout: 30 * time.Second,
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
