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
	"sync"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/acme"
	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

const (
	defaultTickInterval = time.Hour
	jitterWindow        = 10 * time.Minute
	baseBackoff         = 5 * time.Minute
	maxBackoff          = 24 * time.Hour
)

// PushNotifier delivers push notifications to enrolled clients.
type PushNotifier interface {
	Notify(ctx context.Context, cfg *config.ServerConfig, clientName, certName string) error
}

// noopNotifier satisfies PushNotifier and discards all notifications.
type noopNotifier struct{}

func (noopNotifier) Notify(_ context.Context, _ *config.ServerConfig, _, _ string) error { return nil }

// NoopNotifier returns a PushNotifier that does nothing (useful for tests).
func NoopNotifier() PushNotifier { return noopNotifier{} }

// issuer is the subset of acme.Issuer used by Renewer.
type issuer interface {
	Issue(ctx context.Context, cfg *config.ServerConfig, spec config.CertificateSpec) (*acme.Result, error)
}

// Renewer drives certificate renewal for all specs in ServerConfig.
type Renewer struct {
	issuer  issuer
	certs   *store.CertRepo
	push    PushNotifier
	clock   func() time.Time
	mu      sync.Mutex
	backoff map[string]backoffState // keyed by cert name
	wake    chan struct{}
}

type backoffState struct {
	failures int
	next     time.Time
}

// New creates a Renewer. clock may be nil (defaults to time.Now).
func New(iss issuer, certs *store.CertRepo, push PushNotifier, clock func() time.Time) *Renewer {
	if clock == nil {
		clock = time.Now
	}
	if push == nil {
		push = noopNotifier{}
	}
	return &Renewer{
		issuer:  iss,
		certs:   certs,
		push:    push,
		clock:   clock,
		backoff: make(map[string]backoffState),
		wake:    make(chan struct{}, 1),
	}
}

// Run starts a blocking renewal loop. It performs one tick immediately, then
// ticks every defaultTickInterval +/- jitterWindow. Returns when ctx is cancelled.
func (r *Renewer) Run(ctx context.Context, cfg *config.ServerConfig) error {
	return r.RunDynamic(ctx, func() *config.ServerConfig { return cfg })
}

// RunDynamic starts the renewal loop using a fresh configuration snapshot for
// each tick. The snapshot is then used for issuance and push delivery for the
// entire tick, so a concurrent reload cannot mix configuration generations.
func (r *Renewer) RunDynamic(ctx context.Context, current func() *config.ServerConfig) error {
	if current == nil {
		return fmt.Errorf("scheduler configuration source is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.tickCurrent(ctx, current); err != nil {
		log.Printf("sigils: renewal tick failed: %v", err)
	}

	for {
		jitter := time.Duration(rand.Int63n(int64(2*jitterWindow))) - jitterWindow
		interval := defaultTickInterval + jitter
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		case <-r.wake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		if err := r.tickCurrent(ctx, current); err != nil {
			log.Printf("sigils: renewal tick failed: %v", err)
		}
	}
}

func (r *Renewer) tickCurrent(ctx context.Context, current func() *config.ServerConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cfg := current()
	if cfg == nil {
		return fmt.Errorf("scheduler configuration is unavailable")
	}
	return r.tickLocked(ctx, cfg)
}

// Tick iterates all certificate specs and renews those that are due.
// It is exported so tests can drive it directly.
func (r *Renewer) Tick(ctx context.Context, cfg *config.ServerConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tickLocked(ctx, cfg)
}

func (r *Renewer) tickLocked(ctx context.Context, cfg *config.ServerConfig) error {
	if cfg == nil {
		return fmt.Errorf("scheduler configuration is unavailable")
	}
	now := r.clock()
	var errs []error
	for _, spec := range cfg.Certificates {
		if err := r.maybeRenew(ctx, now, cfg, spec); err != nil {
			errs = append(errs, fmt.Errorf("renew %s: %w", spec.Name, err))
		}
	}
	return errors.Join(errs...)
}

// PublishConfig serializes a runtime configuration publication with issuance,
// clears obsolete retry state, and wakes the scheduler for an immediate tick.
// The callback must only perform the atomic publication and must not block.
func (r *Renewer) PublishConfig(ctx context.Context, publish func()) error {
	r.mu.Lock()
	if err := ctx.Err(); err != nil {
		r.mu.Unlock()
		return err
	}
	clear(r.backoff)
	publish()
	r.mu.Unlock()

	select {
	case r.wake <- struct{}{}:
	default:
	}
	return nil
}

// RenewNow immediately issues and persists spec, regardless of its current
// expiry or retry backoff. It shares the same lock as Tick so a manual renewal
// cannot race the periodic scheduler.
func (r *Renewer) RenewNow(ctx context.Context, cfg *config.ServerConfig, spec config.CertificateSpec) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.issueAndPersist(ctx, r.clock(), cfg, spec)
}

// RenewNamed resolves and renews a certificate from a runtime configuration
// snapshot while holding the same lock used by reload and periodic issuance.
func (r *Renewer) RenewNamed(ctx context.Context, current func() *config.ServerConfig, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	cfg := current()
	if cfg == nil {
		return fmt.Errorf("scheduler configuration is unavailable")
	}
	for _, spec := range cfg.Certificates {
		if spec.Name == name {
			return r.issueAndPersist(ctx, r.clock(), cfg, spec)
		}
	}
	return fmt.Errorf("cert %q not found", name)
}

func (r *Renewer) maybeRenew(ctx context.Context, now time.Time, cfg *config.ServerConfig, spec config.CertificateSpec) error {
	// Check backoff: if the cert is in backoff, skip until it's time.
	if bs, ok := r.backoff[spec.Name]; ok && now.Before(bs.next) {
		return nil
	}

	// Look up current cert from store.
	rec, err := r.certs.Get(ctx, spec.Name, nil)
	if errors.Is(err, sql.ErrNoRows) {
		// Cert not yet in store — treat as needing issuance.
		rec = nil
	} else if err != nil {
		return fmt.Errorf("get cert: %w", err)
	}

	renewDays := spec.RenewDaysBefore
	if renewDays == 0 {
		renewDays = config.DefaultRenewDaysBefore
	}
	renewThreshold := time.Duration(renewDays) * 24 * time.Hour

	metadataMatches := rec != nil &&
		rec.CA == spec.CA &&
		slices.Equal(rec.Domains, spec.Domains) &&
		rec.SpecFingerprint == config.CertificateSpecFingerprint(cfg, spec)
	if metadataMatches && now.Add(renewThreshold).Before(rec.NotAfter) {
		// Not yet time to renew.
		return nil
	}

	return r.issueAndPersist(ctx, now, cfg, spec)
}

func (r *Renewer) issueAndPersist(ctx context.Context, now time.Time, cfg *config.ServerConfig, spec config.CertificateSpec) error {
	// Issue / renew.
	result, err := r.issuer.Issue(ctx, cfg, spec)
	if err != nil {
		r.recordFailure(spec.Name, now)
		return err
	}

	// Persist.
	newRec := &store.CertRecord{
		Name:            spec.Name,
		CA:              spec.CA,
		Domains:         spec.Domains,
		SpecFingerprint: config.CertificateSpecFingerprint(cfg, spec),
		FullchainPEM:    string(result.Certificate),
		KeyPEM:          string(result.PrivateKey),
		NotAfter:        result.NotAfter,
		Fingerprint:     certificateFingerprint(result.Certificate),
		IssuedAt:        now,
		UpdatedAt:       now,
	}
	if err := r.certs.Upsert(ctx, newRec, nil); err != nil {
		r.recordFailure(spec.Name, now)
		return fmt.Errorf("upsert cert: %w", err)
	}

	// Clear backoff on success.
	delete(r.backoff, spec.Name)

	// Notify subscribers.
	for _, sub := range spec.Subscribers {
		if err := r.push.Notify(ctx, cfg, sub, spec.Name); err != nil {
			log.Printf("sigils: push notification for certificate %s to client %s failed: %v", spec.Name, sub, err)
		}
	}
	return nil
}

func certificateFingerprint(certificate []byte) string {
	sum := sha256.Sum256(certificate)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// recordFailure increments the failure counter and computes next retry time
// using exponential backoff capped at maxBackoff.
func (r *Renewer) recordFailure(name string, now time.Time) {
	bs := r.backoff[name]
	bs.failures++
	delay := baseBackoff * (1 << min(bs.failures-1, 9)) // 2^(f-1) * base, max 2^9=512 * 5min
	if delay > maxBackoff {
		delay = maxBackoff
	}
	bs.next = now.Add(delay)
	r.backoff[name] = bs
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
