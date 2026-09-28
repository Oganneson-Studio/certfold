// Package scheduler implements the certificate renewal loop for sigils.
package scheduler

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Oganneson-Studio/sigil/internal/acme"
	"github.com/Oganneson-Studio/sigil/internal/config"
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
// defaultTickInterval +/- jitterWindow, at the earliest stored retry time if
// that comes first, or when woken.
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
		retryAt, err := r.tick(ctx, current)
		if err != nil {
			log.Printf("sigils: renewal tick failed: %v", err)
		}

		jitter := time.Duration(rand.Int63n(int64(2*jitterWindow))) - jitterWindow
		interval := defaultTickInterval + jitter
		if !retryAt.IsZero() {
			interval = min(interval, retryAt.Sub(r.clock()))
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
// being issued, without waiting for them. It returns the earliest retry time
// still ahead, or the zero time if no certificate is in backoff.
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
	var retryAt time.Time
	for _, spec := range cfg.Certificates {
		if next := nextAttempt[spec.Name]; now.Before(next) {
			if retryAt.IsZero() || next.Before(retryAt) {
				retryAt = next
			}
			continue
		}
		if !due(now, cfg, spec, stored[spec.Name]) {
			continue
		}
		lock := r.lock(spec.Name)
		select {
		case lock <- struct{}{}:
		default:
			continue // already being issued
		}
		name := spec.Name
		r.wg.Go(func() {
			if err := r.issueLocked(ctx, current, name, lock); err != nil {
				log.Printf("sigils: renewal of certificate %s failed: %v", name, err)
			}
		})
	}
	return retryAt, nil
}

// due reports whether spec needs issuance: nothing is stored for its current
// specification, or the stored certificate is within its renewal window.
func due(now time.Time, cfg *config.ServerConfig, spec config.CertificateSpec, rec *store.CertRecord) bool {
	renewDays := spec.RenewDaysBefore
	if renewDays == 0 {
		renewDays = config.DefaultRenewDaysBefore
	}
	renewThreshold := time.Duration(renewDays) * 24 * time.Hour

	metadataMatches := rec != nil &&
		rec.CA == spec.CA &&
		slices.Equal(rec.Domains, spec.Domains) &&
		rec.SpecFingerprint == config.CertificateSpecFingerprint(cfg, spec)
	return !metadataMatches || !now.Add(renewThreshold).Before(rec.NotAfter)
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
	return r.issueLocked(ctx, current, name, lock)
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
// then releases the certificate's lock, which the caller holds.
func (r *Renewer) issueLocked(ctx context.Context, current func() *config.ServerConfig, name string, lock chan struct{}) error {
	wake := false
	err := acquire(ctx, r.slots)
	if err == nil {
		wake, err = r.issue(ctx, current, name)
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
// due under the new one, or a retry time was stored that the loop's timer
// does not know about yet.
func (r *Renewer) issue(ctx context.Context, current func() *config.ServerConfig, name string) (bool, error) {
	cfg := current()
	spec, ok := specNamed(cfg, name)
	if !ok {
		return false, fmt.Errorf("cert %q not found", name)
	}
	fp := config.CertificateSpecFingerprint(cfg, spec)
	result, err := r.issuer.Issue(ctx, cfg, spec)
	if err != nil {
		// Its text can quote the ACME CA and the DNS provider API, and
		// RenewNamed hands it over IPC to a terminal.
		err = issuerError{err}
	}
	now := r.clock()
	if err != nil && ctx.Err() != nil {
		// Shutdown or an abandoned manual renewal, not a verdict on the configuration.
		return false, err
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
			log.Printf("sigils: discarding the certificate issued for %s: its configuration changed during issuance", name)
			return true, fmt.Errorf("cert %q changed during issuance; the certificate was discarded", name)
		}
		if err = r.save(dbCtx, spec, fp, result, now); err == nil {
			r.genMu.RUnlock()
			r.stored()
			return false, nil
		}
	}
	if latest != cfg {
		// A reload replaced the configuration during the attempt, perhaps
		// fixing the DNS credentials that made it fail; the fingerprint covers
		// neither. The woken tick retries under the new generation at once.
		r.genMu.RUnlock()
		return true, err
	}
	backoffErr := r.backoff(dbCtx, name, now, err)
	r.genMu.RUnlock()
	if backoffErr != nil {
		// Without a stored retry time, waking would retry at once.
		log.Printf("sigils: record issuance failure of certificate %s: %v", name, backoffErr)
		return false, err
	}
	// The loop set its timer before this attempt ended; wake it to plan for
	// the new retry time.
	return true, err
}

// save stores a certificate issued for spec and records the attempt as a
// success, in one transaction: otherwise a failure to record the status would
// leave the certificate stored, and fetched by clients, while the attempt
// counts as failed and the stored callback does not run. The caller holds
// genMu for reading.
//
// The store has a single connection, which the transaction holds until it
// ends: a call inside it that is not given tx waits forever.
func (r *Renewer) save(ctx context.Context, spec config.CertificateSpec, fp string, result *acme.Result, now time.Time) error {
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
		IssuedAt:        now,
		UpdatedAt:       now,
	}, tx); err != nil {
		return fmt.Errorf("upsert cert: %w", err)
	}
	if err := r.db.Issuance.Upsert(ctx, &store.IssuanceStatus{Name: spec.Name, LastAttemptAt: now}, tx); err != nil {
		return fmt.Errorf("record issuance status: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// backoff records a failed attempt of the named certificate together with its
// next retry time. The caller holds genMu for reading.
func (r *Renewer) backoff(ctx context.Context, name string, now time.Time, cause error) error {
	failures := 1
	prev, err := r.db.Issuance.Get(ctx, name, nil)
	switch {
	case err == nil:
		failures = prev.Failures + 1
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	return r.db.Issuance.Upsert(ctx, &store.IssuanceStatus{
		Name:          name,
		Failures:      failures,
		LastError:     lastError(cause),
		LastAttemptAt: now,
		NextAttemptAt: now.Add(retryDelay(failures)),
	}, nil)
}

// retryDelay is the backoff after the given number of consecutive failures:
// baseBackoff doubled for each failure after the first, capped at maxBackoff.
func retryDelay(failures int) time.Duration {
	return min(baseBackoff<<min(max(failures-1, 0), 9), maxBackoff) // 5min<<9 is already past the cap
}

// lastError prepares an issuance error for storage. It can quote responses of
// the ACME CA and the DNS provider API, and the CLI prints it to a terminal as
// is, so control characters become spaces and the length is bounded.
// strings.Map also turns invalid UTF-8 into U+FFFD.
func lastError(err error) string {
	msg := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, err.Error())
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
