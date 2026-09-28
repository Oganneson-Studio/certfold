package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"time"

	"github.com/Oganneson-Studio/sigil/pkg/proto"
)

// baseBackoff and maxBackoff bound the sleep after a round with an error: it
// starts at baseBackoff and doubles up to maxBackoff. Variables only so tests
// can shorten them.
var (
	baseBackoff = 5 * time.Second
	maxBackoff  = 5 * time.Minute
)

// syncTimeout bounds one GET /v1/sync of the loop, which the server holds for
// up to proto.SyncMaxWait before it answers 304.
const syncTimeout = proto.SyncMaxWait + 30*time.Second

// syncResult is an answer to GET /v1/sync. A 200 sets modified, with the
// client's view and its ETag; a 304 means the view has not changed since the
// ETag sent as If-None-Match.
type syncResult struct {
	modified bool
	view     []proto.CertSummary
	etag     string
}

// syncLoop runs rounds until ctx is cancelled. A round without an error is
// followed by the next one at once, so between two changes the loop waits in
// GET /v1/sync. After a round with an error the loop sleeps, from baseBackoff
// doubling up to maxBackoff, ±10 %, until a reload wakes it.
func (c *Client) syncLoop(ctx context.Context) error {
	var backoff time.Duration
	for {
		voided, err := c.syncRound(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		switch {
		case voided:
			continue
		case err == nil:
			backoff = 0
			continue
		case backoff == 0:
			backoff = baseBackoff
		default:
			backoff = min(2*backoff, maxBackoff)
		}
		// A reload that came while no sleep was running left its signal in
		// reloadCh and ends this sleep early, one round early at most.
		timer := time.NewTimer(jitter(backoff, jitterPct))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-c.reloadCh:
			timer.Stop()
		case <-timer.C:
		}
	}
}

// syncRound runs one round of the loop:
//  1. Under pullMu, renew the identity when due, then take the server URL,
//     HTTP client and etag for the request and register its cancel in the
//     same section. A failed renewal is an error of the round, but the
//     request still goes out with the current identity, which stays valid
//     until it expires.
//  2. Without pullMu, send GET /v1/sync, with If-None-Match when etag is set,
//     so IPC fetches and reloads never wait for the server to answer.
//  3. Under pullMu again, apply the view of a 200. Then, whatever the
//     answer, reconcile the outputs, run the pending on_change programs and
//     record the outcome.
//
// voided reports that Reload, an IPC fetch or an identity switch cancelled
// the request: the round did nothing, and the next one should start at once.
func (c *Client) syncRound(ctx context.Context) (voided bool, err error) {
	c.pullMu.Lock()
	defer c.pullMu.Unlock()

	var errs []error
	if err := c.renewIdentityLocked(ctx); err != nil {
		errs = append(errs, fmt.Errorf("renew client identity: %w", err))
	}
	reqCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	c.syncCancel = cancel
	serverURL, etag := c.cfg.Client.ServerURL, c.etag
	// c.http gives up after httpTimeout, before the server answers a request
	// it holds. Share its transport and redirect policy.
	syncClient := *c.http
	syncClient.Timeout = syncTimeout

	c.pullMu.Unlock()
	result, err := requestSync(reqCtx, &syncClient, serverURL, etag)
	var answeredAt time.Time
	if err == nil {
		answeredAt = time.Now()
	}
	c.pullMu.Lock()

	switch {
	case ctx.Err() != nil:
		return false, ctx.Err()
	case reqCtx.Err() != nil:
		// Reload, IPC fetches and identity switches cancel under pullMu, so
		// the answer may have arrived before the cancel, while this round
		// waited for the lock. Either way it must not be applied: it answers
		// a request made with what Reload or the switch replaced, or holds a
		// view that may be older than the fetch's, and applying it would also
		// set the etag Reload cleared.
		return true, nil
	case err != nil:
		errs = append(errs, fmt.Errorf("sync: %w", err))
	case result.modified:
		if err := c.applyViewLocked(reqCtx, result, ""); err != nil {
			errs = append(errs, err)
		}
	}
	// Reconcile after every answer, including 304 and errors: this is how
	// outputs deleted or changed on disk come back.
	if err := c.reconcileLocked(); err != nil {
		errs = append(errs, err)
	}
	err = errors.Join(errs...)
	c.recordPullLocked(answeredAt, err)
	return false, err
}

// requestSync sends GET /v1/sync, with If-None-Match when etag is set.
func requestSync(ctx context.Context, httpClient *http.Client, serverURL, etag string) (*syncResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL+"/v1/sync", nil)
	if err != nil {
		return nil, err
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return &syncResult{}, nil
	case http.StatusOK:
		result := &syncResult{modified: true, etag: resp.Header.Get("ETag")}
		if err := json.NewDecoder(resp.Body).Decode(&result.view); err != nil {
			return nil, fmt.Errorf("decode: %w", err)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("server returned %d", resp.StatusCode)
	}
}

// applyViewLocked makes the store hold the certificates of the view of a 200:
//   - It downloads each certificate whose fingerprint differs from the stored
//     one, or that is not stored, and force as well when the view lists it.
//     The store keeps the fingerprint of the bundle, which may be newer than
//     the view's. A bundle whose name is not the one asked for, or whose key
//     does not belong to its certificate, is not stored: bad material must
//     neither replace outputs nor run on_change.
//   - A downloaded fingerprint that differs from the stored one sets
//     hook_pending when the certificate has an on_change program. A forced
//     download of the stored fingerprint only repairs material that differs,
//     without setting it.
//   - Certificates the view does not list leave the store. Their outputs stay
//     as they are, and their programs do not run.
//
// The store is written, once, only if it changed; if the write fails, the
// store in memory stays as it was. c.etag becomes the ETag of the view if all
// of this succeeded and is cleared otherwise, so the next round asks for the
// whole view again.
func (c *Client) applyViewLocked(ctx context.Context, result *syncResult, force string) error {
	next := make(map[string]storedCert, len(result.view))
	var errs []error
	for _, summary := range result.view {
		name := summary.Name
		stored, ok := c.store[name]
		if ok && stored.Fingerprint == summary.Fingerprint && name != force {
			next[name] = stored
			continue
		}
		bundle, err := c.getBundle(ctx, name)
		if err == nil {
			err = checkBundle(name, bundle)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("bundle %s: %w", name, err))
			if ok {
				next[name] = stored
			}
			continue
		}
		cert := storedCert{
			Fingerprint:  bundle.Fingerprint,
			FullchainPEM: bundle.FullchainPEM,
			KeyPEM:       bundle.KeyPEM,
			HookPending:  stored.HookPending,
		}
		if (!ok || cert.Fingerprint != stored.Fingerprint) && len(c.cfg.Certificates[name].OnChange) > 0 {
			cert.HookPending = true
		}
		next[name] = cert
	}
	if !maps.Equal(next, c.store) {
		if err := saveStore(c.cfg.Client.DataDir, next); err != nil {
			errs = append(errs, fmt.Errorf("save store: %w", err))
		} else {
			// next carries the bits in memory, unsaved ones included.
			c.store = next
			c.storeUnsaved = false
		}
	}
	if len(errs) > 0 {
		c.etag = ""
		return errors.Join(errs...)
	}
	c.etag = result.etag
	return nil
}

// checkBundle rejects a bundle that is not the named certificate's, or whose
// private key does not belong to its certificate.
func checkBundle(name string, bundle *proto.CertBundle) error {
	if bundle.Name != name {
		return fmt.Errorf("server sent certificate %q", bundle.Name)
	}
	if _, err := tls.X509KeyPair([]byte(bundle.FullchainPEM), []byte(bundle.KeyPEM)); err != nil {
		return err
	}
	return nil
}
