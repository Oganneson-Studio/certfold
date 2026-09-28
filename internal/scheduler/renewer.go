// Package scheduler implements the certificate renewal loop for sigils.
package scheduler

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Oganneson-Studio/sigil/internal/acme"
	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/logging"
	"github.com/Oganneson-Studio/sigil/internal/renewal"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

const (
	defaultTickInterval = time.Hour
	jitterWindow        = 10 * time.Minute
	baseBackoff         = 5 * time.Minute
	maxBackoff          = 24 * time.Hour

	// maxConcurrentIssuance bounds the issuances running at once, including
	// manual renewals. It is not configurable: four stays far below Let's
	// Encrypt's 300 new orders per 3 hours and the rate limits of DNS
	// provider APIs.
	maxConcurrentIssuance = 4

	// maxLastErrorBytes bounds the stored error of a failed issuance.
	maxLastErrorBytes = 1 << 10
)

// issuer is the subset of acme.Issuer used by Renewer.
type issuer interface {
	Issue(ctx context.Context, cfg *config.ServerConfig, spec config.CertificateSpec) (*acme.Result, error)
}

// Renewer drives certificate renewal for all specs in ServerConfig.
//
// An issuance holds its certificate's lock, then an issuance slot, then genMu
// for reading while it stores the outcome. Always taken in that order, these
// cannot deadlock.
type Renewer struct {
	issuer issuer
	db     *store.DB
	// stored is called once for every issued certificate stored, after genMu
	// is released. The daemon passes a function that wakes the clients
	// waiting in GET /v1/sync.
	stored func()
	clock  func() time.Time

	// genMu orders storing an issuance outcome (read) against publishing a
	// configuration generation (write). Both sections are short database
	// writes; nothing that talks to the network may run under it.
	genMu sync.RWMutex

	mu    sync.Mutex
	locks map[string]chan struct{} // per-certificate locks, created on first use and never removed
	slots chan struct{}            // issuance slots, maxConcurrentIssuance places

	wg   sync.WaitGroup // issuances started by ticks
	wake chan struct{}
}

// New creates a Renewer. stored may be nil (does nothing) and must not block;
// clock may be nil (defaults to time.Now).
func New(iss issuer, db *store.DB, stored func(), clock func() time.Time) *Renewer {
	if clock == nil {
		clock = time.Now
	}
	if stored == nil {
		stored = func() {}
	}
	return &Renewer{
		issuer: iss,
		db:     db,
		stored: stored,
		clock:  clock,
		locks:  make(map[string]chan struct{}),
		slots:  make(chan struct{}, maxConcurrentIssuance),
		wake:   make(chan struct{}, 1),
	}
}

// RunDynamic runs the renewal loop until ctx is cancelled. Each tick reads a
// fresh configuration snapshot and starts the due issuances without waiting
// for them. The first tick runs immediately; later ones run every
// defaultTickInterval +/- jitterWindow, at the earliest stored retry time or
// renewal time if that comes first, or when woken.
//
// Once ctx is cancelled, issuances still waiting for a slot give up, and
// RunDynamic returns after the running ones have stored their outcome: lego
// cannot be interrupted, and a certificate the CA has issued should not be
// thrown away.
func (r *Renewer) RunDynamic(ctx context.Context, current func() *config.ServerConfig) error {
	if current == nil {
		return fmt.Errorf("scheduler configuration source is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	defer r.wg.Wait()

	for {
		wakeAt, err := r.tick(ctx, current)
		if err != nil {
			slog.Error("renewal tick failed", "error", err)
		}

		jitter := time.Duration(rand.Int63n(int64(2*jitterWindow))) - jitterWindow
		interval := defaultTickInterval + jitter
		if !wakeAt.IsZero() {
			interval = min(interval, wakeAt.Sub(r.clock()))
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		case <-r.wake:
			timer.Stop()
		}
	}
}

// tick starts an issuance for every certificate that is due and not already
// being issued, without waiting for them. A certificate is due when nothing
// is stored for its current specification, or when the renewal plan of the
// stored one says so. tick returns when the loop must tick again at the
// latest: the earliest retry time or renewal time still ahead, or the zero
// time if there is none. The certificates it starts or skips as already
// being issued count for none, lest the loop wake at once: the end of each
// issuance wakes it instead.
func (r *Renewer) tick(ctx context.Context, current func() *config.ServerConfig) (time.Time, error) {
	cfg := current()
	if cfg == nil {
		return time.Time{}, fmt.Errorf("scheduler configuration is unavailable")
	}
	recs, err := r.db.Certs.List(ctx, nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("list certs: %w", err)
	}
	statuses, err := r.db.Issuance.List(ctx, nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("list issuance status: %w", err)
	}
	stored := make(map[string]*store.CertRecord, len(recs))
	for _, rec := range recs {
		stored[rec.Name] = rec
	}
	nextAttempt := make(map[string]time.Time, len(statuses))
	for _, st := range statuses {
		nextAttempt[st.Name] = st.NextAttemptAt
	}

	now := r.clock()
	var wakeAt time.Time
	wakeBy := func(at time.Time) {
		if wakeAt.IsZero() || at.Before(wakeAt) {
			wakeAt = at
		}
	}
	for _, spec := range cfg.Certificates {
		if next := nextAttempt[spec.Name]; now.Before(next) {
			wakeBy(next)
			continue
		}
		reason := "new"
		if rec := stored[spec.Name]; matches(cfg, spec, rec) {
			at, source := r.RenewalPlan(rec)
			if now.Before(at) {
				wakeBy(at)
				continue
			}
			reason = source
		}
		lock := r.lock(spec.Name)
		select {
		case lock <- struct{}{}:
		default:
			continue // already being issued
		}
		name := spec.Name
		// issue reports its outcome as events. The other errors come from a
		// shutdown, or from a reload that removed the certificate meanwhile.
		r.wg.Go(func() { _ = r.issueLocked(ctx, current, name, reason, lock) })
	}
	return wakeAt, nil
}

// matches reports whether rec holds material issued for spec as cfg
// configures it.
func matches(cfg *config.ServerConfig, spec config.CertificateSpec, rec *store.CertRecord) bool {
	return rec != nil &&
		rec.CA == spec.CA &&
		slices.Equal(rec.Domains, spec.Domains) &&
		rec.SpecFingerprint == config.CertificateSpecFingerprint(cfg, spec)
}

// RenewalPlan returns when the stored certificate rec is due for renewal, and
// the rule that says so: "ratio", the share of its lifetime that
// renewal.RenewAt leaves. A certificate that cannot be read gets the zero
// time, which is due at once. The IPC listing of certificates calls it too,
// concurrently with the scheduler.
func (r *Renewer) RenewalPlan(rec *store.CertRecord) (time.Time, string) {
	at, _ := renewal.RenewAt(rec.FullchainPEM) // the zero time on error
	return at, "ratio"
}

// dueOnArrival returns when the certificate in fullchainPEM, issued at now, is
// due for renewal, or an error if it is due already or cannot be read. Stored
// as a success, such a certificate would be issued again at once, and so on
// without end.
func dueOnArrival(fullchainPEM []byte, now time.Time) (time.Time, error) {
	at, err := renewal.RenewAt(string(fullchainPEM))
	if err != nil {
		return time.Time{}, fmt.Errorf("issued certificate is already due for renewal: %w", err)
	}
	if now.Before(at) {
		return at, nil
	}
	block, _ := pem.Decode(fullchainPEM)
	leaf, _ := x509.ParseCertificate(block.Bytes) // as RenewAt did
	return at, fmt.Errorf("issued certificate is already due for renewal (lifetime %s, renewal due %s)",
		leaf.NotAfter.Sub(leaf.NotBefore), at.UTC().Format(time.RFC3339))
}

// PublishConfig publishes a configuration generation without waiting for
// in-flight issuance: an issuance whose specification changed meanwhile
// discards its result when storing it. It clears the retry backoff of every
// certificate, keeping the last error, and wakes the scheduler for an
// immediate tick. The callback must only perform the atomic publication and
// must not block.
func (r *Renewer) PublishConfig(ctx context.Context, publish func()) error {
	r.genMu.Lock()
	if err := ctx.Err(); err != nil {
		r.genMu.Unlock()
		return err
	}
	if err := r.db.Issuance.ClearBackoff(ctx, nil); err != nil {
		r.genMu.Unlock()
		return fmt.Errorf("clear issuance backoff: %w", err)
	}
	publish()
	r.genMu.Unlock()

	r.wakeUp()
	return nil
}

// RenewNamed issues the named certificate from the running configuration and
// stores it, regardless of its expiry or retry backoff. It first waits for an
// issuance of the same certificate that is already running, then for an
// issuance slot; cancelling ctx stops either wait.
func (r *Renewer) RenewNamed(ctx context.Context, current func() *config.ServerConfig, name string) error {
	if _, ok := specNamed(current(), name); !ok {
		return fmt.Errorf("cert %q not found", name)
	}
	lock := r.lock(name)
	if err := acquire(ctx, lock); err != nil {
		return err
	}
	return r.issueLocked(ctx, current, name, "manual", lock)
}

// Issuing reports whether an issuance of the named certificate is running or
// waiting for a slot.
func (r *Renewer) Issuing(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.locks[name]) > 0
}

func (r *Renewer) lock(name string) chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	lock, ok := r.locks[name]
	if !ok {
		lock = make(chan struct{}, 1)
		r.locks[name] = lock
	}
	return lock
}

// acquire takes a place in sem, a certificate lock or the issuance slots,
// waiting until one is free. A done ctx always wins, even over a place that
// frees up at the same moment, so nothing new starts once shutdown begins.
func acquire(ctx context.Context, sem chan struct{}) error {
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		<-sem
		return err
	}
	return nil
}

func (r *Renewer) wakeUp() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// issueLocked issues the named certificate once an issuance slot is free,
// then releases the certificate's lock, which the caller holds. reason says
// why it is issued: "new", "manual" or the source of its renewal plan.
func (r *Renewer) issueLocked(ctx context.Context, current func() *config.ServerConfig, name, reason string, lock chan struct{}) error {
	wake := false
	err := acquire(ctx, r.slots)
	if err == nil {
		wake, err = r.issue(ctx, current, name, reason)
		<-r.slots
	}
	<-lock
	if wake {
		// Only now can the woken tick take the certificate's lock.
		r.wakeUp()
	}
	return err
}

// issue obtains the named certificate using the running configuration and
// stores the outcome. It reports whether the scheduler should tick again:
// either the configuration changed during the attempt, so the certificate is
// due under the new one, or a certificate or a retry time was stored whose
// renewal or retry time the loop's timer does not know about yet.
//
// A certificate that is due for renewal as it arrives is stored all the same,
// being the newest the clients can have, but the attempt counts as failed, so
// that the next one waits out a backoff that grows as long as the CA issues
// such certificates, rather than follow at once.
//
// issue reports the attempt and its outcome as events, once genMu is
// released.
func (r *Renewer) issue(ctx context.Context, current func() *config.ServerConfig, name, reason string) (bool, error) {
	cfg := current()
	spec, ok := specNamed(cfg, name)
	if !ok {
		return false, fmt.Errorf("cert %q not found", name)
	}
	fp := config.CertificateSpecFingerprint(cfg, spec)
	slog.Info("certificate issuance started", "cert", name, "reason", reason)
	result, err := r.issuer.Issue(ctx, cfg, spec)
	if err != nil {
		// Its text can quote the ACME CA and the DNS provider API, and
		// RenewNamed hands it over IPC to a terminal.
		err = issuerError{err}
	}
	now := r.clock()
	if err != nil && ctx.Err() != nil {
		// Shutdown or an abandoned manual renewal, not a verdict on the configuration.
		slog.Error("certificate issuance failed", "cert", name, "error", err)
		return false, err
	}
	var renewAt time.Time
	var dueErr error
	if err == nil {
		renewAt, dueErr = dueOnArrival(result.Certificate, now)
	}

	// The outcome is checked against the running configuration and stored
	// under the generation read lock, so no reload can publish in between.
	// PublishConfig waits for this section: database calls only.
	dbCtx := context.WithoutCancel(ctx)
	r.genMu.RLock()
	latest := current()
	if err == nil {
		spec, ok = specNamed(latest, name)
		if !ok || config.CertificateSpecFingerprint(latest, spec) != fp {
			r.genMu.RUnlock()
			slog.Warn("issued certificate discarded", "cert", name)
			return true, fmt.Errorf("cert %q changed during issuance; the certificate was discarded", name)
		}
		status := &store.IssuanceStatus{Name: name, LastAttemptAt: now}
		if dueErr != nil {
			status, err = r.failed(dbCtx, name, now, dueErr)
		}
		if err == nil {
			err = r.save(dbCtx, spec, fp, result, status)
		}
		if err == nil {
			r.genMu.RUnlock()
			r.stored()
			slog.Info("certificate issued", "cert", name, "not_after", result.NotAfter,
				"renew_at", renewAt, "fingerprint", certificateFingerprint(result.Certificate))
			if dueErr != nil {
				slog.Error("certificate issuance failed", "cert", name, "error", dueErr,
					"failures", status.Failures, "next_attempt", status.NextAttemptAt)
			}
			return true, dueErr
		}
	}
	if latest != cfg {
		// A reload replaced the configuration during the attempt, perhaps
		// fixing the DNS credentials that made it fail; the fingerprint covers
		// neither. The woken tick retries under the new generation at once.
		r.genMu.RUnlock()
		slog.Error("certificate issuance failed", "cert", name, "error", err)
		return true, err
	}
	status, backoffErr := r.backoff(dbCtx, name, now, err)
	r.genMu.RUnlock()
	if backoffErr != nil {
		// Without a stored retry time, waking would retry at once.
		slog.Error("certificate issuance failed", "cert", name, "error", err)
		slog.Error("record issuance failure failed", "cert", name, "error", backoffErr)
		return false, err
	}
	slog.Error("certificate issuance failed", "cert", name, "error", err,
		"failures", status.Failures, "next_attempt", status.NextAttemptAt)
	// The loop set its timer before this attempt ended; wake it to plan for
	// the new retry time.
	return true, err
}

// save stores a certificate issued for spec, at status.LastAttemptAt, and
// records the outcome of the attempt, status, in one transaction: otherwise a
// failure to record the status would leave the certificate stored, and
// fetched by clients, while the attempt counts as failed and the stored
// callback does not run. The caller holds genMu for reading.
//
// The store has a single connection, which the transaction holds until it
// ends: a call inside it that is not given tx waits forever.
func (r *Renewer) save(ctx context.Context, spec config.CertificateSpec, fp string, result *acme.Result, status *store.IssuanceStatus) error {
	tx, err := r.db.BeginTx(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // does nothing once committed
	if err := r.db.Certs.Upsert(ctx, &store.CertRecord{
		Name:            spec.Name,
		CA:              spec.CA,
		Domains:         spec.Domains,
		SpecFingerprint: fp,
		FullchainPEM:    string(result.Certificate),
		KeyPEM:          string(result.PrivateKey),
		NotAfter:        result.NotAfter,
		Fingerprint:     certificateFingerprint(result.Certificate),
		IssuedAt:        status.LastAttemptAt,
		UpdatedAt:       status.LastAttemptAt,
	}, tx); err != nil {
		return fmt.Errorf("upsert cert: %w", err)
	}
	if err := r.db.Issuance.Upsert(ctx, status, tx); err != nil {
		return fmt.Errorf("record issuance status: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// backoff records a failed attempt of the named certificate together with its
// next retry time, and returns what it recorded. The caller holds genMu for
// reading.
func (r *Renewer) backoff(ctx context.Context, name string, now time.Time, cause error) (*store.IssuanceStatus, error) {
	status, err := r.failed(ctx, name, now, cause)
	if err != nil {
		return nil, err
	}
	if err := r.db.Issuance.Upsert(ctx, status, nil); err != nil {
		return nil, err
	}
	return status, nil
}

// failed returns the issuance status of an attempt of the named certificate
// that failed at now: one failure more than the stored status has, and a
// retry time that backs off accordingly. The caller holds genMu for reading,
// which keeps PublishConfig from clearing the stored status meanwhile.
func (r *Renewer) failed(ctx context.Context, name string, now time.Time, cause error) (*store.IssuanceStatus, error) {
	failures := 1
	prev, err := r.db.Issuance.Get(ctx, name, nil)
	switch {
	case err == nil:
		failures = prev.Failures + 1
	case !errors.Is(err, sql.ErrNoRows):
		return nil, err
	}
	return &store.IssuanceStatus{
		Name:          name,
		Failures:      failures,
		LastError:     lastError(cause),
		LastAttemptAt: now,
		NextAttemptAt: now.Add(retryDelay(failures)),
	}, nil
}

// retryDelay is the backoff after the given number of consecutive failures:
// baseBackoff doubled for each failure after the first, capped at maxBackoff.
func retryDelay(failures int) time.Duration {
	return min(baseBackoff<<min(max(failures-1, 0), 9), maxBackoff) // 5min<<9 is already past the cap
}

// lastError prepares an issuance error for storage. It can quote responses of
// the ACME CA and the DNS provider API, and the CLI prints it to a terminal as
// is, so control characters become spaces and the length is bounded.
// strings.Map also turns invalid UTF-8 into U+FFFD. It can also quote the URL
// of a request to the DNS provider API, whose query may hold credentials, so
// the query of every URL is withheld.
func lastError(err error) string {
	msg := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, err.Error())
	// Before the cut, which must bound the longer text of a short query.
	msg = logging.RedactURLQueries(msg)
	if len(msg) > maxLastErrorBytes {
		cut := maxLastErrorBytes
		for !utf8.RuneStart(msg[cut]) {
			cut--
		}
		msg = msg[:cut]
	}
	return msg
}

// issuerError reads like lastError; Unwrap keeps the issuer error for errors.Is and errors.As.
type issuerError struct{ err error }

func (e issuerError) Error() string { return lastError(e.err) }
func (e issuerError) Unwrap() error { return e.err }

func specNamed(cfg *config.ServerConfig, name string) (config.CertificateSpec, bool) {
	if cfg != nil {
		for _, spec := range cfg.Certificates {
			if spec.Name == name {
				return spec, true
			}
		}
	}
	return config.CertificateSpec{}, false
}

func certificateFingerprint(certificate []byte) string {
	sum := sha256.Sum256(certificate)
	return "sha256:" + hex.EncodeToString(sum[:])
}
