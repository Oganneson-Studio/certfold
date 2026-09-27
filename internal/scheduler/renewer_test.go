package scheduler

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/acme"
	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

type mockIssuer struct {
	mu     sync.Mutex
	calls  int
	cfg    *config.ServerConfig
	result *acme.Result
	err    error
	called chan struct{}
}

func (m *mockIssuer) Issue(_ context.Context, cfg *config.ServerConfig, _ config.CertificateSpec) (*acme.Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	m.cfg = cfg
	if m.called != nil {
		select {
		case m.called <- struct{}{}:
		default:
		}
	}
	return m.result, m.err
}

type recordingNotifier struct {
	mu     sync.Mutex
	calls  []notifyCall
	cfg    *config.ServerConfig
	called chan struct{}
}

type notifyCall struct{ client, cert string }

func (n *recordingNotifier) Notify(_ context.Context, cfg *config.ServerConfig, client, cert string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.cfg = cfg
	n.calls = append(n.calls, notifyCall{client, cert})
	if n.called != nil {
		select {
		case n.called <- struct{}{}:
		default:
		}
	}
	return nil
}

func (n *recordingNotifier) Calls() []notifyCall {
	n.mu.Lock()
	defer n.mu.Unlock()
	cp := make([]notifyCall, len(n.calls))
	copy(cp, n.calls)
	return cp
}

type blockingIssuer struct {
	started chan *config.ServerConfig
	release chan struct{}
	result  *acme.Result
}

func (i *blockingIssuer) Issue(ctx context.Context, cfg *config.ServerConfig, _ config.CertificateSpec) (*acme.Result, error) {
	select {
	case i.started <- cfg:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case <-i.release:
		return i.result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func mustOpenDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func minimalCfg(certName string, renewDaysBefore int, subscribers []string) *config.ServerConfig {
	return &config.ServerConfig{
		Certificates: []config.CertificateSpec{
			{
				Name:            certName,
				Domains:         []string{"example.com"},
				CA:              "le",
				RenewDaysBefore: renewDaysBefore,
				Subscribers:     subscribers,
			},
		},
	}
}

func successResult(notAfter time.Time) *acme.Result {
	return &acme.Result{
		Domain:      "example.com",
		Certificate: []byte("---cert---"),
		PrivateKey:  []byte("---key---"),
		NotAfter:    notAfter,
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestTick_DueRenewal: cert expires soon → issuer called, cert stored.
func TestTick_DueRenewal(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := now.Add(20 * 24 * time.Hour) // 20 days → below 30-day threshold

	mi := &mockIssuer{result: successResult(now.Add(90 * 24 * time.Hour))}
	rn := &recordingNotifier{}
	r := New(mi, db.Certs, rn, func() time.Time { return now })

	cfg := minimalCfg("api-prod", 30, []string{"web-1"})

	// Pre-seed an existing (soon-to-expire) cert record.
	_ = db.Certs.Upsert(ctx, &store.CertRecord{
		Name:            "api-prod",
		CA:              "le",
		Domains:         []string{"example.com"},
		SpecFingerprint: config.CertificateSpecFingerprint(cfg, cfg.Certificates[0]),
		NotAfter:        notAfter,
		UpdatedAt:       now,
	}, nil)

	if err := r.Tick(ctx, cfg); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if mi.calls != 1 {
		t.Errorf("Issue called %d times, want 1", mi.calls)
	}
	if mi.cfg != cfg || rn.cfg != cfg {
		t.Fatal("issuer and push notifier did not receive the tick configuration snapshot")
	}

	// Verify stored cert was updated.
	rec, err := db.Certs.Get(ctx, "api-prod", nil)
	if err != nil {
		t.Fatalf("get cert: %v", err)
	}
	if string(rec.FullchainPEM) != "---cert---" {
		t.Errorf("cert not updated in store: %q", rec.FullchainPEM)
	}
	if rec.Fingerprint == "" {
		t.Error("certificate fingerprint was not stored")
	}
	if !rec.IssuedAt.Equal(now) {
		t.Errorf("IssuedAt = %v, want %v", rec.IssuedAt, now)
	}
}

func TestRun_TicksImmediately(t *testing.T) {
	db := mustOpenDB(t)
	called := make(chan struct{}, 1)
	mi := &mockIssuer{
		result: successResult(time.Now().Add(90 * 24 * time.Hour)),
		called: called,
	}
	r := New(mi, db.Certs, nil, time.Now)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.Run(ctx, minimalCfg("api-prod", 30, nil))
	}()

	select {
	case <-called:
		cancel()
	case <-time.After(time.Second):
		cancel()
		t.Fatal("Run did not perform an initial tick")
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want context.Canceled", err)
	}
}

func TestPublishConfigWaitsForInFlightTick(t *testing.T) {
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	oldCfg := minimalCfg("api-prod", 30, []string{"web-1"})
	newCfg := minimalCfg("api-prod", 30, []string{"web-2"})
	newCfg.Certificates[0].Domains = []string{"new.example.com"}
	issuer := &blockingIssuer{
		started: make(chan *config.ServerConfig, 1),
		release: make(chan struct{}),
		result:  successResult(now.Add(90 * 24 * time.Hour)),
	}
	r := New(issuer, db.Certs, nil, func() time.Time { return now })

	tickDone := make(chan error, 1)
	go func() { tickDone <- r.Tick(context.Background(), oldCfg) }()
	if got := <-issuer.started; got != oldCfg {
		t.Fatal("in-flight tick did not use the old generation")
	}

	var current atomic.Pointer[config.ServerConfig]
	current.Store(oldCfg)
	reloadDone := make(chan error, 1)
	go func() {
		reloadDone <- r.PublishConfig(context.Background(), func() { current.Store(newCfg) })
	}()
	select {
	case err := <-reloadDone:
		t.Fatalf("reload completed before in-flight tick: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(issuer.release)
	if err := <-tickDone; err != nil {
		t.Fatal(err)
	}
	if err := <-reloadDone; err != nil {
		t.Fatal(err)
	}
	if current.Load() != newCfg {
		t.Fatal("new generation was not published")
	}
}

func TestPublishConfigWakesSchedulerAndClearsBackoff(t *testing.T) {
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	oldCfg := minimalCfg("api-prod", 30, []string{"web-1"})
	newCfg := minimalCfg("api-prod", 30, []string{"web-2"})
	newCfg.Certificates[0].Domains = []string{"new.example.com"}
	if err := db.Certs.Upsert(context.Background(), &store.CertRecord{
		Name: "api-prod", CA: "le", Domains: []string{"example.com"},
		SpecFingerprint: config.CertificateSpecFingerprint(oldCfg, oldCfg.Certificates[0]),
		NotAfter:        now.Add(90 * 24 * time.Hour), UpdatedAt: now,
	}, nil); err != nil {
		t.Fatal(err)
	}

	called := make(chan struct{}, 1)
	issuer := &mockIssuer{result: successResult(now.Add(90 * 24 * time.Hour)), called: called}
	notified := make(chan struct{}, 1)
	notifier := &recordingNotifier{called: notified}
	r := New(issuer, db.Certs, notifier, func() time.Time { return now })
	r.backoff["api-prod"] = backoffState{failures: 3, next: now.Add(24 * time.Hour)}
	var current atomic.Pointer[config.ServerConfig]
	current.Store(oldCfg)
	loaded := make(chan struct{}, 1)
	currentConfig := func() *config.ServerConfig {
		select {
		case loaded <- struct{}{}:
		default:
		}
		return current.Load()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.RunDynamic(ctx, currentConfig) }()
	<-loaded

	if err := r.PublishConfig(context.Background(), func() { current.Store(newCfg) }); err != nil {
		t.Fatal(err)
	}
	select {
	case <-called:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("configuration reload did not wake the scheduler")
	}
	select {
	case <-notified:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("reload tick did not notify the new subscriber")
	}
	if issuer.cfg != newCfg || notifier.cfg != newCfg {
		t.Fatal("reload tick did not consistently use the new generation")
	}
	if len(r.backoff) != 0 {
		t.Fatalf("backoff was not cleared: %+v", r.backoff)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("RunDynamic returned %v", err)
	}
}

// TestTick_NotDue: cert still has plenty of time → issuer NOT called.
func TestTick_NotDue(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := now.Add(60 * 24 * time.Hour) // 60 days → above 30-day threshold

	mi := &mockIssuer{}
	r := New(mi, db.Certs, nil, func() time.Time { return now })

	cfg := minimalCfg("api-prod", 30, nil)

	_ = db.Certs.Upsert(ctx, &store.CertRecord{
		Name:            "api-prod",
		CA:              "le",
		Domains:         []string{"example.com"},
		SpecFingerprint: config.CertificateSpecFingerprint(cfg, cfg.Certificates[0]),
		NotAfter:        notAfter,
		UpdatedAt:       now,
	}, nil)

	_ = r.Tick(ctx, cfg)
	if mi.calls != 0 {
		t.Errorf("Issue should not be called when cert is not due, got %d calls", mi.calls)
	}
}

func TestRenewNowForcesNotDueCertificate(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	mi := &mockIssuer{result: successResult(now.Add(120 * 24 * time.Hour))}
	r := New(mi, db.Certs, nil, func() time.Time { return now })
	cfg := minimalCfg("api-prod", 30, nil)
	spec := cfg.Certificates[0]
	if err := db.Certs.Upsert(ctx, &store.CertRecord{
		Name: "api-prod", CA: "le", Domains: spec.Domains,
		SpecFingerprint: config.CertificateSpecFingerprint(cfg, spec),
		NotAfter:        now.Add(90 * 24 * time.Hour), UpdatedAt: now,
	}, nil); err != nil {
		t.Fatal(err)
	}
	r.backoff[spec.Name] = backoffState{failures: 2, next: now.Add(time.Hour)}

	if err := r.RenewNow(ctx, cfg, spec); err != nil {
		t.Fatalf("RenewNow: %v", err)
	}
	if mi.calls != 1 {
		t.Fatalf("Issue calls = %d, want 1", mi.calls)
	}
	if _, ok := r.backoff[spec.Name]; ok {
		t.Fatal("successful manual renewal did not clear backoff")
	}
	rec, err := db.Certs.Get(ctx, spec.Name, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec.FullchainPEM != "---cert---" || !rec.IssuedAt.Equal(now) {
		t.Fatalf("stored record = %+v", rec)
	}
}

func TestRenewNamedRenewsOnlyTheExactName(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	mi := &mockIssuer{result: successResult(now.Add(90 * 24 * time.Hour))}
	r := New(mi, db.Certs, nil, func() time.Time { return now })
	cfg := minimalCfg("api-prod", 30, nil)
	stage := cfg.Certificates[0]
	stage.Name = "api-stage"
	cfg.Certificates = append(cfg.Certificates, stage)
	current := func() *config.ServerConfig { return cfg }

	if err := r.RenewNamed(ctx, current, "api-prod"); err != nil {
		t.Fatalf("RenewNamed: %v", err)
	}
	if mi.calls != 1 || mi.cfg != cfg {
		t.Fatalf("Issue calls = %d with config %p, want 1 call with the live snapshot %p", mi.calls, mi.cfg, cfg)
	}
	if _, err := db.Certs.Get(ctx, "api-prod", nil); err != nil {
		t.Fatalf("renewed certificate was not stored: %v", err)
	}
	if _, err := db.Certs.Get(ctx, "api-stage", nil); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unrequested certificate was stored, err = %v", err)
	}

	err := r.RenewNamed(ctx, current, "API-PROD")
	if err == nil || !strings.Contains(err.Error(), `cert "API-PROD" not found`) {
		t.Fatalf("case-mismatched name error = %v", err)
	}
	if mi.calls != 1 {
		t.Fatalf("unknown name triggered issuance; calls = %d", mi.calls)
	}
}

func TestRenewNamedPropagatesIssuerFailure(t *testing.T) {
	want := errors.New("acme failed")
	r := New(&mockIssuer{err: want}, mustOpenDB(t).Certs, nil, nil)
	cfg := minimalCfg("api-prod", 30, nil)
	err := r.RenewNamed(context.Background(), func() *config.ServerConfig { return cfg }, "api-prod")
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

func TestTickRenewsWhenConfiguredDomainsChange(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	mi := &mockIssuer{result: successResult(now.Add(90 * 24 * time.Hour))}
	r := New(mi, db.Certs, nil, func() time.Time { return now })
	cfg := minimalCfg("api-prod", 30, nil)
	cfg.Certificates[0].Domains = []string{"new.example.com"}
	if err := db.Certs.Upsert(ctx, &store.CertRecord{
		Name: "api-prod", CA: "le", Domains: []string{"old.example.com"},
		NotAfter: now.Add(80 * 24 * time.Hour), UpdatedAt: now,
	}, nil); err != nil {
		t.Fatal(err)
	}

	if err := r.Tick(ctx, cfg); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if mi.calls != 1 {
		t.Fatalf("Issue calls = %d, want 1 after domain change", mi.calls)
	}
	rec, err := db.Certs.Get(ctx, "api-prod", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rec.Domains, []string{"new.example.com"}) {
		t.Fatalf("stored domains = %v", rec.Domains)
	}
}

func TestTickRenewsWhenConfiguredKeyTypeChanges(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	issuer := &mockIssuer{result: successResult(now.Add(90 * 24 * time.Hour))}
	r := New(issuer, db.Certs, nil, func() time.Time { return now })
	oldCfg := minimalCfg("api-prod", 30, nil)
	oldCfg.Certificates[0].KeyType = "ec256"
	newCfg := minimalCfg("api-prod", 30, nil)
	newCfg.Certificates[0].KeyType = "rsa2048"
	if err := db.Certs.Upsert(ctx, &store.CertRecord{
		Name: "api-prod", CA: "le", Domains: []string{"example.com"},
		SpecFingerprint: config.CertificateSpecFingerprint(oldCfg, oldCfg.Certificates[0]),
		NotAfter:        now.Add(80 * 24 * time.Hour), UpdatedAt: now,
	}, nil); err != nil {
		t.Fatal(err)
	}

	if err := r.Tick(ctx, newCfg); err != nil {
		t.Fatal(err)
	}
	if issuer.calls != 1 {
		t.Fatalf("Issue calls = %d, want 1", issuer.calls)
	}
	rec, err := db.Certs.Get(ctx, "api-prod", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec.SpecFingerprint != config.CertificateSpecFingerprint(newCfg, newCfg.Certificates[0]) {
		t.Fatal("stored certificate fingerprint does not match new key type")
	}
}

// TestTick_NoCertInStore: no record in store → treated as needing issuance.
func TestTick_NoCertInStore(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	mi := &mockIssuer{result: successResult(now.Add(90 * 24 * time.Hour))}
	r := New(mi, db.Certs, nil, func() time.Time { return now })

	_ = r.Tick(ctx, minimalCfg("api-prod", 30, nil))
	if mi.calls != 1 {
		t.Errorf("Issue should be called when cert absent, got %d calls", mi.calls)
	}
}

// TestTick_FailureBackoff: issuer fails → backoff applied, not retried immediately.
func TestTick_FailureBackoff(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	mi := &mockIssuer{err: errors.New("ACME unavailable")}
	r := New(mi, db.Certs, nil, func() time.Time { return now })

	cfg := minimalCfg("api-prod", 30, nil)

	if err := r.Tick(ctx, cfg); err == nil { // first call -> failure, backoff set
		t.Fatal("expected Tick to report the issuer failure")
	}
	if mi.calls != 1 {
		t.Fatalf("expected 1 call after first failure, got %d", mi.calls)
	}

	// Second Tick at same time → still in backoff window, no second call.
	_ = r.Tick(ctx, cfg)
	if mi.calls != 1 {
		t.Errorf("second Tick should be suppressed by backoff, got %d calls", mi.calls)
	}

	// Tick after backoff expires → retried.
	r.clock = func() time.Time { return now.Add(baseBackoff + time.Second) }
	mi.err = nil
	mi.result = successResult(now.Add(90 * 24 * time.Hour))
	_ = r.Tick(ctx, cfg)
	if mi.calls != 2 {
		t.Errorf("expected retry after backoff, got %d calls", mi.calls)
	}
}

// TestTick_ExponentialBackoff: multiple failures → delays grow.
func TestTick_ExponentialBackoff(t *testing.T) {
	r := &Renewer{
		backoff: make(map[string]backoffState),
		clock:   time.Now,
	}
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	delays := []time.Duration{}
	for i := 0; i < 5; i++ {
		r.recordFailure("cert", now)
		bs := r.backoff["cert"]
		delays = append(delays, bs.next.Sub(now))
	}

	for i := 1; i < len(delays); i++ {
		if delays[i] <= delays[i-1] {
			t.Errorf("delay[%d]=%v should be > delay[%d]=%v", i, delays[i], i-1, delays[i-1])
		}
	}
}

// TestTick_BackoffCapped: backoff never exceeds maxBackoff.
func TestTick_BackoffCapped(t *testing.T) {
	r := &Renewer{
		backoff: make(map[string]backoffState),
		clock:   time.Now,
	}
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	for i := 0; i < 20; i++ {
		r.recordFailure("cert", now)
	}
	bs := r.backoff["cert"]
	if bs.next.Sub(now) > maxBackoff+time.Second {
		t.Errorf("backoff exceeded maxBackoff: got %v", bs.next.Sub(now))
	}
}

// TestTick_PushNotify: successful renewal notifies all subscribers.
func TestTick_PushNotify(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	mi := &mockIssuer{result: successResult(now.Add(90 * 24 * time.Hour))}
	rn := &recordingNotifier{}
	r := New(mi, db.Certs, rn, func() time.Time { return now })

	cfg := minimalCfg("api-prod", 30, []string{"web-1", "web-2"})
	_ = r.Tick(ctx, cfg)

	calls := rn.Calls()
	if len(calls) != 2 {
		t.Fatalf("expected 2 push notifications, got %d", len(calls))
	}
	clients := map[string]bool{}
	for _, c := range calls {
		if c.cert != "api-prod" {
			t.Errorf("unexpected cert %q in notification", c.cert)
		}
		clients[c.client] = true
	}
	if !clients["web-1"] || !clients["web-2"] {
		t.Errorf("not all subscribers notified: %v", clients)
	}
}

// TestTick_SuccessClearsBackoff: after a successful renewal, backoff is cleared.
func TestTick_SuccessClearsBackoff(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	mi := &mockIssuer{err: errors.New("fail")}
	r := New(mi, db.Certs, nil, func() time.Time { return now })
	cfg := minimalCfg("api-prod", 30, nil)

	_ = r.Tick(ctx, cfg) // first failure
	if _, ok := r.backoff["api-prod"]; !ok {
		t.Fatal("expected backoff to be set after failure")
	}

	// Now succeed after backoff expires.
	r.clock = func() time.Time { return now.Add(maxBackoff + time.Hour) }
	mi.err = nil
	mi.result = successResult(now.Add(90 * 24 * time.Hour))
	_ = r.Tick(ctx, cfg)

	if _, ok := r.backoff["api-prod"]; ok {
		t.Error("expected backoff to be cleared after success")
	}
}

// TestNoopNotifier: NoopNotifier returns no error.
func TestNoopNotifier(t *testing.T) {
	n := NoopNotifier()
	if err := n.Notify(context.Background(), &config.ServerConfig{}, "client", "cert"); err != nil {
		t.Errorf("NoopNotifier.Notify returned error: %v", err)
	}
}
