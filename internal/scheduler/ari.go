package scheduler

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"math/rand"
	"net"
	"time"

	"github.com/Oganneson-Studio/certfold/internal/acme"
	"github.com/Oganneson-Studio/certfold/internal/config"
	"github.com/Oganneson-Studio/certfold/internal/store"
)

// Renewal information (RFC 9773): the CA's suggested renewal window of each
// stored certificate. It is kept in memory only, as the RFC has a client ask
// again right after issuance anyway: a restart costs one query per
// certificate.
const (
	// ariDefaultInterval is how long to wait before asking again when the CA
	// sent no Retry-After, and after an error other than a timeout (RFC 9773,
	// section 4.3.3).
	ariDefaultInterval = 6 * time.Hour
	// ariTimeoutRetry is how long to wait before asking again after a query
	// timed out.
	ariTimeoutRetry = time.Hour
	// ariMinInterval and ariMaxInterval bound the Retry-After of the CA (RFC
	// 9773, section 4.3.2).
	ariMinInterval = time.Minute
	ariMaxInterval = 24 * time.Hour
	// ariUnsupportedRecheck is how long to wait before asking again for a
	// certificate the CA offers no renewal info for.
	ariUnsupportedRecheck = 24 * time.Hour
)

// errWindowPassed fails the first renewal window of a certificate this process
// issued when the whole window has passed already. Renewals the CA directs are
// exempt from Let's Encrypt's rate limits, so a CA that answered every new
// certificate so would have it issued again and again without end.
var errWindowPassed = errors.New("renewal window of a newly issued certificate has already passed")

// ariState is what the scheduler knows of the renewal window of one stored
// certificate.
type ariState struct {
	fingerprint string            // the CertRecord.Fingerprint of the certificate it is about
	window      *acme.RenewalInfo // the latest valid window, nil until one arrives
	pick        time.Time         // the renewal time drawn from window, kept while the window stays the same
	nextCheck   time.Time         // when to ask again; the zero time asks at the next tick
	unsupported bool              // the CA offers no renewal info for the certificate
	lastErr     string            // the error of the latest failed query, reported once
}

// ariCheck is a stored certificate whose renewal info to ask for, and the
// configuration generation it is asked under.
type ariCheck struct {
	name, fingerprint string
	fullchainPEM      []byte
	issuedAt          time.Time
	cfg               *config.ServerConfig
	spec              config.CertificateSpec
}

// planRenewalInfo follows the renewal info of the certificates of cfg that
// have matching material in stored, and drops what it knows of the others.
// It starts asking for the renewal info of those it is due for, unless a
// query is running already, whose end wakes the loop to plan again. It does
// not ask for an expired certificate (RFC 9773, section 4.3), or for one being
// issued: issuing names those the tick started or found being issued. It
// returns the earliest time still ahead at which it is due for one, or the
// zero time.
func (r *Renewer) planRenewalInfo(ctx context.Context, current func() *config.ServerConfig, cfg *config.ServerConfig,
	stored map[string]*store.CertRecord, issuing map[string]bool, now time.Time) time.Time {
	follow := make(map[string]*store.CertRecord)
	for _, spec := range cfg.Certificates {
		if rec := stored[spec.Name]; matches(cfg, spec, rec) {
			follow[spec.Name] = rec
			// Before ariMu, which must not be held while taking another lock.
			issuing[spec.Name] = issuing[spec.Name] || r.Issuing(spec.Name)
		}
	}

	var checks []ariCheck
	var wakeAt time.Time
	r.ariMu.Lock()
	for name := range r.ari {
		if follow[name] == nil {
			delete(r.ari, name)
			delete(r.ariTrips, name)
		}
	}
	for _, spec := range cfg.Certificates {
		rec := follow[spec.Name]
		if rec == nil {
			continue
		}
		st := r.ari[spec.Name]
		if st == nil || st.fingerprint != rec.Fingerprint {
			// A new certificate is asked about at once (RFC 9773, section 4.3).
			st = &ariState{fingerprint: rec.Fingerprint}
			r.ari[spec.Name] = st
		}
		switch {
		case !now.Before(rec.NotAfter) || issuing[spec.Name]:
		case now.Before(st.nextCheck):
			if wakeAt.IsZero() || st.nextCheck.Before(wakeAt) {
				wakeAt = st.nextCheck
			}
		default:
			checks = append(checks, ariCheck{
				name: spec.Name, fingerprint: rec.Fingerprint, fullchainPEM: []byte(rec.FullchainPEM),
				issuedAt: rec.IssuedAt, cfg: cfg, spec: spec,
			})
		}
	}
	start := len(checks) > 0 && !r.ariChecking
	if start {
		r.ariChecking = true
	}
	r.ariMu.Unlock()

	if start {
		// Not in wg, so that shutdown does not wait for lego's timeouts. It
		// records its answers in memory, except the backoff of a passed window
		// in the store, and drops those that come once ctx is done.
		go r.checkRenewalInfo(ctx, current, checks)
	}
	return wakeAt
}

// checkRenewalInfo asks the CA for the renewal info of each of checks in turn
// and records the answers, then wakes the loop to plan for them. It holds no
// lock while it asks, so a CA that is slow to answer delays neither issuance,
// reloads nor the IPC listing of certificates. Once ctx is cancelled it asks
// no more, and drops the answer it was waiting for: the store may be closing.
//
// A certificate can start being issued after the tick planned the check; the
// answer then concerns the certificate being replaced. That does no harm: once
// the new one is stored, the next tick asks about it afresh.
func (r *Renewer) checkRenewalInfo(ctx context.Context, current func() *config.ServerConfig, checks []ariCheck) {
	for _, c := range checks {
		if ctx.Err() != nil {
			break
		}
		info, err := r.issuer.RenewalInfo(c.cfg, c.spec, c.fullchainPEM)
		if ctx.Err() != nil {
			break
		}
		r.recordRenewalInfo(ctx, current, c, info, err)
	}
	r.ariMu.Lock()
	r.ariChecking = false
	r.ariMu.Unlock()
	r.wakeUp()
}

// recordRenewalInfo records the answer to c, unless another certificate was
// stored meanwhile, and reports it as events.
//
// A valid window keeps its renewal time for as long as the CA keeps the
// window. A failed query keeps the window the CA sent last. The first window of
// a certificate this process issued that has passed already fails the issuance
// as the guard of errWindowPassed: the renewal waits out a backoff that doubles
// with every certificate the CA answers so, counted by ariTrips, since storing
// each one cleared the stored failures.
func (r *Renewer) recordRenewalInfo(ctx context.Context, current func() *config.ServerConfig, c ariCheck, info *acme.RenewalInfo, err error) {
	now := r.clock()
	var events []func()
	var guard *store.IssuanceStatus

	r.ariMu.Lock()
	st := r.ari[c.name]
	if st == nil || st.fingerprint != c.fingerprint {
		r.ariMu.Unlock()
		return
	}
	switch {
	case err == nil:
		first := st.window == nil
		updated := first || !info.Start.Equal(st.window.Start) || !info.End.Equal(st.window.End)
		if updated {
			// Uniformly at random within the window (RFC 9773, section 4.2).
			st.pick = info.Start
			if d := info.End.Sub(info.Start); d > 0 {
				st.pick = st.pick.Add(time.Duration(rand.Int63n(int64(d))))
			}
		}
		st.window = info
		st.nextCheck = now.Add(min(max(cmp.Or(info.RetryAfter, ariDefaultInterval), ariMinInterval), ariMaxInterval))
		st.unsupported, st.lastErr = false, ""
		if now.Before(info.End) {
			delete(r.ariTrips, c.name)
		} else if first && !c.issuedAt.Before(r.started) {
			r.ariTrips[c.name]++
			trips := r.ariTrips[c.name]
			// RenewalPlan holds the renewal back until the retry time: a tick
			// between this section and storing the backoff reads no backoff.
			st.pick = now.Add(retryDelay(trips))
			st.lastErr = lastError(errWindowPassed)
			guard = &store.IssuanceStatus{
				Name: c.name, Failures: trips, LastError: st.lastErr,
				LastAttemptAt: c.issuedAt, NextAttemptAt: st.pick,
			}
		}
		if updated {
			events = append(events, windowUpdatedEvent(c.name, info, st.pick))
		}
		if guard != nil {
			events = append(events, queryFailedEvent(c.name, st.lastErr, st.nextCheck))
		}
	case errors.Is(err, acme.ErrNoRenewalInfo):
		if !st.unsupported {
			events = append(events, func() { slog.Info("CA offers no renewal info", "cert", c.name, "ca", c.spec.CA) })
		}
		st.unsupported, st.window, st.lastErr = true, nil, ""
		st.nextCheck = now.Add(ariUnsupportedRecheck)
	default:
		retry := ariDefaultInterval
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			retry = ariTimeoutRetry
		}
		st.nextCheck = now.Add(retry)
		// It can quote the CA's answer, which the events show in a terminal.
		if msg := lastError(err); msg != st.lastErr {
			st.lastErr = msg
			events = append(events, queryFailedEvent(c.name, msg, st.nextCheck))
		}
	}
	r.ariMu.Unlock()

	if guard != nil {
		// Like issue: a reload since the tick cleared the backoffs of the
		// generation this one belongs to.
		var err error
		r.genMu.RLock()
		if current() == c.cfg {
			err = r.storeGuard(context.WithoutCancel(ctx), c.fingerprint, guard)
		}
		r.genMu.RUnlock()
		if err != nil {
			events = append(events, func() { slog.Error("record issuance failure failed", "cert", c.name, "error", err) })
		}
	}
	for _, event := range events {
		event()
	}
}

// storeGuard stores status, the backoff of the passed window of the certificate
// with the given fingerprint, unless another certificate has been stored since
// the tick, as by a manual renewal: the window is not about that one. The
// transaction orders it against save, which also runs under genMu for reading.
// The caller holds genMu for reading.
func (r *Renewer) storeGuard(ctx context.Context, fingerprint string, status *store.IssuanceStatus) error {
	tx, err := r.db.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }() // does nothing once committed
	rec, err := r.db.Certs.Get(ctx, status.Name, tx)
	if err != nil || rec.Fingerprint != fingerprint {
		return err
	}
	if err := r.db.Issuance.Upsert(ctx, status, tx); err != nil {
		return err
	}
	return tx.Commit()
}

func windowUpdatedEvent(name string, info *acme.RenewalInfo, renewAt time.Time) func() {
	return func() {
		attrs := []any{"cert", name, "window_start", info.Start, "window_end", info.End, "renew_at", renewAt}
		if info.ExplanationURL != "" {
			attrs = append(attrs, "explanation_url", info.ExplanationURL)
		}
		slog.Info("renewal window updated", attrs...)
	}
}

func queryFailedEvent(name, msg string, nextCheck time.Time) func() {
	return func() { slog.Warn("renewal info query failed", "cert", name, "error", msg, "next_check", nextCheck) }
}

// ariPick returns the renewal time drawn from the renewal window of rec, if
// the CA sent one for it.
func (r *Renewer) ariPick(rec *store.CertRecord) (time.Time, bool) {
	r.ariMu.Lock()
	defer r.ariMu.Unlock()
	st := r.ari[rec.Name]
	if st == nil || st.window == nil || st.fingerprint != rec.Fingerprint {
		return time.Time{}, false
	}
	return st.pick, true
}

// recheckRenewalInfo has the next tick ask again for the renewal info of every
// certificate: a reload lets the operator see at once a window the CA changed.
func (r *Renewer) recheckRenewalInfo() {
	r.ariMu.Lock()
	defer r.ariMu.Unlock()
	for _, st := range r.ari {
		st.nextCheck = time.Time{}
	}
}

// resetARITrips forgets the passed windows of the named certificate: it was
// issued other than as the CA directed.
func (r *Renewer) resetARITrips(name string) {
	r.ariMu.Lock()
	defer r.ariMu.Unlock()
	delete(r.ariTrips, name)
}

// replacing returns the stored certificate an issuance for spec replaces, to
// name in the order (RFC 9773, section 5), or nil. Only a renewal replaces it:
// the stored material matches spec, and the latest attempt did not fail. A CA
// can refuse the name for reasons lego does not handle, such as an order from
// another account; the next attempt then leaves it out.
func (r *Renewer) replacing(ctx context.Context, cfg *config.ServerConfig, spec config.CertificateSpec) []byte {
	rec, err := r.db.Certs.Get(ctx, spec.Name, nil)
	if err != nil || !matches(cfg, spec, rec) {
		return nil
	}
	status, err := r.db.Issuance.Get(ctx, spec.Name, nil)
	if err == nil && status.Failures > 0 || err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	return []byte(rec.FullchainPEM)
}
