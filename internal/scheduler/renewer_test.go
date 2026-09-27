package scheduler

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

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

// gatedIssuer hands every Issue call to the test and blocks it until the test
// settles it. Like lego, it ignores ctx.
type gatedIssuer struct {
	calls  chan *issueCall
	result *acme.Result

	mu     sync.Mutex
	active int
	peak   int
}

type issueCall struct {
	cfg     *config.ServerConfig
	spec    config.CertificateSpec
	outcome chan error
}

func newGatedIssuer(notAfter time.Time) *gatedIssuer {
	return &gatedIssuer{calls: make(chan *issueCall), result: successResult(notAfter)}
}

func (g *gatedIssuer) Issue(_ context.Context, cfg *config.ServerConfig, spec config.CertificateSpec) (*acme.Result, error) {
	g.mu.Lock()
	g.active++
	g.peak = max(g.peak, g.active)
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		g.active--
		g.mu.Unlock()
	}()

	call := &issueCall{cfg: cfg, spec: spec, outcome: make(chan error, 1)}
	g.calls <- call
	if err := <-call.outcome; err != nil {
		return nil, err
	}
	return g.result, nil
}

// Peak returns the largest number of Issue calls that ran at once.
func (g *gatedIssuer) Peak() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.peak
}

// next returns the next Issue call, failing the test if none starts in time.
func (g *gatedIssuer) next(t *testing.T) *issueCall {
	t.Helper()
	select {
	case call := <-g.calls:
		return call
	case <-time.After(5 * time.Second):
		t.Fatal("no issuance started")
		return nil
	}
}

// none fails the test if an Issue call starts within a short grace period.
func (g *gatedIssuer) none(t *testing.T) {
	t.Helper()
	select {
	case call := <-g.calls:
		t.Fatalf("unexpected issuance of %s", call.spec.Name)
	case <-time.After(100 * time.Millisecond):
	}
}

func (c *issueCall) succeed()       { c.outcome <- nil }
func (c *issueCall) fail(err error) { c.outcome <- err }

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

// multiCfg returns a configuration with one certificate per name.
func multiCfg(names ...string) *config.ServerConfig {
	cfg := &config.ServerConfig{}
	for _, name := range names {
		cfg.Certificates = append(cfg.Certificates, config.CertificateSpec{
			Name: name, Domains: []string{name + ".example.com"}, CA: "le",
		})
	}
	return cfg
}

func successResult(notAfter time.Time) *acme.Result {
	return &acme.Result{
		Domain:      "example.com",
		Certificate: []byte("---cert---"),
		PrivateKey:  []byte("---key---"),
		NotAfter:    notAfter,
	}
}

func static(cfg *config.ServerConfig) func() *config.ServerConfig {
	return func() *config.ServerConfig { return cfg }
}

// tickAndWait runs one tick and waits for the issuances it started.
func tickAndWait(ctx context.Context, r *Renewer, cfg *config.ServerConfig) error {
	_, err := r.tick(ctx, static(cfg))
	r.wg.Wait()
	return err
}

// renewAsync runs RenewNamed in the background and returns its result channel.
func renewAsync(ctx context.Context, r *Renewer, current func() *config.ServerConfig, name string) <-chan error {
	done := make(chan error, 1)
	go func() { done <- r.RenewNamed(ctx, current, name) }()
	return done
}

func receive(t *testing.T, ch <-chan error, what string) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not return", what)
		return nil
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func mustStatus(t *testing.T, db *store.DB, name string) *store.IssuanceStatus {
	t.Helper()
	st, err := db.Issuance.Get(context.Background(), name, nil)
	if err != nil {
		t.Fatalf("issuance status of %s: %v", name, err)
	}
	return st
}

func assertStatus(t *testing.T, db *store.DB, want store.IssuanceStatus) {
	t.Helper()
	got := mustStatus(t, db, want.Name)
	if got.Failures != want.Failures || got.LastError != want.LastError ||
		!got.LastAttemptAt.Equal(want.LastAttemptAt) || !got.NextAttemptAt.Equal(want.NextAttemptAt) {
		t.Fatalf("issuance status = %+v, want %+v", got, want)
	}
}

func assertNoStatus(t *testing.T, db *store.DB, name string) {
	t.Helper()
	if st, err := db.Issuance.Get(context.Background(), name, nil); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("issuance status of %s = %+v, %v; want none", name, st, err)
	}
}

func assertNoCert(t *testing.T, db *store.DB, name string) {
	t.Helper()
	if rec, err := db.Certs.Get(context.Background(), name, nil); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("stored certificate %s = %+v, %v; want none", name, rec, err)
	}
}

// ---------------------------------------------------------------------------
// Scheduling
// ---------------------------------------------------------------------------

// TestTick_DueRenewal: cert expires soon → issuer called, cert stored.
func TestTick_DueRenewal(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := now.Add(20 * 24 * time.Hour) // 20 days → below 30-day threshold

	mi := &mockIssuer{result: successResult(now.Add(90 * 24 * time.Hour))}
	rn := &recordingNotifier{}
	r := New(mi, db.Certs, db.Issuance, rn, func() time.Time { return now })

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

	if err := tickAndWait(ctx, r, cfg); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if mi.calls != 1 {
		t.Errorf("Issue called %d times, want 1", mi.calls)
	}
	if mi.cfg != cfg || rn.cfg != cfg {
		t.Fatal("issuer and push notifier did not receive the running configuration snapshot")
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

func TestRunDynamic_TicksImmediately(t *testing.T) {
	db := mustOpenDB(t)
	called := make(chan struct{}, 1)
	mi := &mockIssuer{
		result: successResult(time.Now().Add(90 * 24 * time.Hour)),
		called: called,
	}
	r := New(mi, db.Certs, db.Issuance, nil, time.Now)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- r.RunDynamic(ctx, static(minimalCfg("api-prod", 30, nil)))
	}()

	select {
	case <-called:
		cancel()
	case <-time.After(time.Second):
		cancel()
		t.Fatal("RunDynamic did not perform an initial tick")
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("RunDynamic returned %v, want context.Canceled", err)
	}
}

// TestTick_NotDue: cert still has plenty of time → issuer NOT called.
func TestTick_NotDue(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := now.Add(60 * 24 * time.Hour) // 60 days → above 30-day threshold

	mi := &mockIssuer{}
	r := New(mi, db.Certs, db.Issuance, nil, func() time.Time { return now })

	cfg := minimalCfg("api-prod", 30, nil)

	_ = db.Certs.Upsert(ctx, &store.CertRecord{
		Name:            "api-prod",
		CA:              "le",
		Domains:         []string{"example.com"},
		SpecFingerprint: config.CertificateSpecFingerprint(cfg, cfg.Certificates[0]),
		NotAfter:        notAfter,
		UpdatedAt:       now,
	}, nil)

	_ = tickAndWait(ctx, r, cfg)
	if mi.calls != 0 {
		t.Errorf("Issue should not be called when cert is not due, got %d calls", mi.calls)
	}
}

func TestTickRenewsWhenConfiguredDomainsChange(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	mi := &mockIssuer{result: successResult(now.Add(90 * 24 * time.Hour))}
	r := New(mi, db.Certs, db.Issuance, nil, func() time.Time { return now })
	cfg := minimalCfg("api-prod", 30, nil)
	cfg.Certificates[0].Domains = []string{"new.example.com"}
	if err := db.Certs.Upsert(ctx, &store.CertRecord{
		Name: "api-prod", CA: "le", Domains: []string{"old.example.com"},
		NotAfter: now.Add(80 * 24 * time.Hour), UpdatedAt: now,
	}, nil); err != nil {
		t.Fatal(err)
	}

	if err := tickAndWait(ctx, r, cfg); err != nil {
		t.Fatalf("tick: %v", err)
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
	r := New(issuer, db.Certs, db.Issuance, nil, func() time.Time { return now })
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

	if err := tickAndWait(ctx, r, newCfg); err != nil {
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
	r := New(mi, db.Certs, db.Issuance, nil, func() time.Time { return now })

	_ = tickAndWait(ctx, r, minimalCfg("api-prod", 30, nil))
	if mi.calls != 1 {
		t.Errorf("Issue should be called when cert absent, got %d calls", mi.calls)
	}
}

// TestTick_PushNotify: successful renewal notifies all subscribers.
func TestTick_PushNotify(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	mi := &mockIssuer{result: successResult(now.Add(90 * 24 * time.Hour))}
	rn := &recordingNotifier{}
	r := New(mi, db.Certs, db.Issuance, rn, func() time.Time { return now })

	cfg := minimalCfg("api-prod", 30, []string{"web-1", "web-2"})
	_ = tickAndWait(ctx, r, cfg)

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

// ⑯ A tick skips a certificate whose lock is held and does not wait for the
// issuances it starts.
func TestTickSkipsCertificateBeingIssued(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	iss := newGatedIssuer(now.Add(90 * 24 * time.Hour))
	r := New(iss, db.Certs, db.Issuance, nil, func() time.Time { return now })
	cfg := multiCfg("api-prod", "api-stage")

	renewed := renewAsync(ctx, r, static(cfg), "api-prod")
	held := iss.next(t)

	ticked := make(chan error, 1)
	go func() {
		_, err := r.tick(ctx, static(cfg))
		ticked <- err
	}()
	select {
	case err := <-ticked:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("tick blocked on a certificate being issued")
	}

	// The tick returned while the issuance it started is still running.
	started := iss.next(t)
	if started.spec.Name != "api-stage" {
		t.Fatalf("tick issued %s, want only api-stage", started.spec.Name)
	}
	iss.none(t)
	started.succeed()
	held.succeed()
	if err := receive(t, renewed, "RenewNamed"); err != nil {
		t.Fatal(err)
	}
	r.wg.Wait()
}

// ⑰ The timer wakes the loop at the earliest stored retry time rather than
// after the hourly interval.
func TestTimerWakesAtEarliestRetry(t *testing.T) {
	db := mustOpenDB(t)
	// Stored times have second precision; this retry time is 1-2s ahead, so the
	// first tick must skip the certificate.
	next := time.Now().Truncate(time.Second).Add(2 * time.Second)
	if err := db.Issuance.Upsert(context.Background(), &store.IssuanceStatus{
		Name: "api-prod", Failures: 1, LastError: "CA down",
		LastAttemptAt: next.Add(-baseBackoff), NextAttemptAt: next,
	}, nil); err != nil {
		t.Fatal(err)
	}
	called := make(chan struct{}, 1)
	mi := &mockIssuer{result: successResult(time.Now().Add(90 * 24 * time.Hour)), called: called}
	r := New(mi, db.Certs, db.Issuance, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- r.RunDynamic(ctx, static(minimalCfg("api-prod", 30, nil))) }()

	select {
	case <-called:
		if time.Now().Before(next) {
			t.Fatal("retried before the stored retry time")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the scheduler did not wake at the stored retry time")
	}
	cancel()
	if err := receive(t, done, "RunDynamic"); !errors.Is(err, context.Canceled) {
		t.Fatalf("RunDynamic returned %v", err)
	}
}

// ⑰ A failure's retry time is stored after the tick that started the
// issuance has set its timer, so storing it wakes the loop to plan again.
func TestRecordedBackoffWakesScheduler(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	start := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	var clock atomic.Int64
	clock.Store(start.UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()).UTC() }

	cfg := multiCfg("api-prod", "api-stage")
	stage := cfg.Certificates[1]
	if err := db.Certs.Upsert(ctx, &store.CertRecord{
		Name: stage.Name, CA: stage.CA, Domains: stage.Domains,
		SpecFingerprint: config.CertificateSpecFingerprint(cfg, stage),
		NotAfter:        start.Add(45 * 24 * time.Hour), UpdatedAt: start,
	}, nil); err != nil {
		t.Fatal(err)
	}
	iss := newGatedIssuer(start.Add(90 * 24 * time.Hour))
	r := New(iss, db.Certs, db.Issuance, nil, now)
	runCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- r.RunDynamic(runCtx, static(cfg)) }()

	failing := iss.next(t)
	if failing.spec.Name != "api-prod" {
		t.Fatalf("first issuance = %s, want api-prod", failing.spec.Name)
	}
	// api-stage enters its renewal window while the loop sleeps on its timer.
	failedAt := start.Add(20 * 24 * time.Hour)
	clock.Store(failedAt.UnixNano())
	failing.fail(errors.New("CA down"))

	renewal := iss.next(t)
	if renewal.spec.Name != "api-stage" {
		t.Fatalf("issuance after the failure = %s, want api-stage", renewal.spec.Name)
	}
	renewal.succeed()
	cancel()
	if err := receive(t, done, "RunDynamic"); !errors.Is(err, context.Canceled) {
		t.Fatalf("RunDynamic returned %v", err)
	}
	assertStatus(t, db, store.IssuanceStatus{
		Name: "api-prod", Failures: 1, LastError: "CA down",
		LastAttemptAt: failedAt, NextAttemptAt: failedAt.Add(baseBackoff),
	})
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

// ① Two manual renewals of the same certificate run one after the other.
func TestRenewNamedSerializesSameCertificate(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	iss := newGatedIssuer(now.Add(90 * 24 * time.Hour))
	r := New(iss, db.Certs, db.Issuance, nil, func() time.Time { return now })
	current := static(minimalCfg("api-prod", 30, nil))

	first := renewAsync(ctx, r, current, "api-prod")
	firstCall := iss.next(t)
	second := renewAsync(ctx, r, current, "api-prod")
	iss.none(t)

	firstCall.succeed()
	if err := receive(t, first, "first RenewNamed"); err != nil {
		t.Fatal(err)
	}
	iss.next(t).succeed()
	if err := receive(t, second, "second RenewNamed"); err != nil {
		t.Fatal(err)
	}
	if peak := iss.Peak(); peak != 1 {
		t.Fatalf("peak concurrent issuance of one certificate = %d, want 1", peak)
	}
}

// ② No more than maxConcurrentIssuance issuances run at once.
func TestIssuanceConcurrencyIsBounded(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	iss := newGatedIssuer(now.Add(90 * 24 * time.Hour))
	r := New(iss, db.Certs, db.Issuance, nil, func() time.Time { return now })
	var names []string
	for i := range maxConcurrentIssuance + 2 {
		names = append(names, fmt.Sprintf("cert-%d", i))
	}
	cfg := multiCfg(names...)

	if _, err := r.tick(ctx, static(cfg)); err != nil {
		t.Fatal(err)
	}
	var running []*issueCall
	for range maxConcurrentIssuance {
		running = append(running, iss.next(t))
	}
	iss.none(t)
	for _, call := range running {
		call.succeed()
	}
	for range 2 {
		iss.next(t).succeed()
	}
	r.wg.Wait()

	if peak := iss.Peak(); peak != maxConcurrentIssuance {
		t.Fatalf("peak concurrent issuance = %d, want %d", peak, maxConcurrentIssuance)
	}
	for _, name := range names {
		if _, err := db.Certs.Get(ctx, name, nil); err != nil {
			t.Fatalf("certificate %s was not stored: %v", name, err)
		}
	}
}

// ③ An issuance blocked on one certificate does not hold up another.
func TestBlockedIssuanceDoesNotDelayOtherCertificates(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	iss := newGatedIssuer(now.Add(90 * 24 * time.Hour))
	r := New(iss, db.Certs, db.Issuance, nil, func() time.Time { return now })
	current := static(multiCfg("api-prod", "api-stage"))

	blocked := renewAsync(ctx, r, current, "api-prod")
	blockedCall := iss.next(t)
	other := renewAsync(ctx, r, current, "api-stage")
	otherCall := iss.next(t)
	if otherCall.spec.Name != "api-stage" {
		t.Fatalf("second issuance = %s, want api-stage", otherCall.spec.Name)
	}
	otherCall.succeed()
	if err := receive(t, other, "RenewNamed(api-stage)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Certs.Get(ctx, "api-stage", nil); err != nil {
		t.Fatalf("api-stage was not stored while api-prod was blocked: %v", err)
	}
	assertNoCert(t, db, "api-prod")

	blockedCall.succeed()
	if err := receive(t, blocked, "RenewNamed(api-prod)"); err != nil {
		t.Fatal(err)
	}
}

// ⑮ Issuing reports a held certificate lock, including while the issuance
// waits for a slot.
func TestIssuingReportsHeldLock(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	iss := newGatedIssuer(now.Add(90 * 24 * time.Hour))
	r := New(iss, db.Certs, db.Issuance, nil, func() time.Time { return now })
	var names []string
	for i := range maxConcurrentIssuance + 1 {
		names = append(names, fmt.Sprintf("cert-%d", i))
	}
	cfg := multiCfg(names...)

	for _, name := range names {
		if r.Issuing(name) {
			t.Fatalf("Issuing(%s) = true before any issuance", name)
		}
	}
	if _, err := r.tick(ctx, static(cfg)); err != nil {
		t.Fatal(err)
	}
	var running []*issueCall
	for range maxConcurrentIssuance {
		running = append(running, iss.next(t))
	}
	for _, name := range names {
		if !r.Issuing(name) {
			t.Fatalf("Issuing(%s) = false while it runs or waits for a slot", name)
		}
	}
	if r.Issuing("unknown") {
		t.Fatal("Issuing(unknown) = true")
	}
	for _, call := range running {
		call.succeed()
	}
	iss.next(t).succeed()
	r.wg.Wait()
	for _, name := range names {
		if r.Issuing(name) {
			t.Fatalf("Issuing(%s) = true after the issuance finished", name)
		}
	}
}

// ⑭ On shutdown RunDynamic returns only after running issuances have stored
// their certificate, and issuances waiting for a slot never start.
func TestRunDynamicWaitsForInFlightIssuanceOnShutdown(t *testing.T) {
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	iss := newGatedIssuer(now.Add(90 * 24 * time.Hour))
	r := New(iss, db.Certs, db.Issuance, nil, func() time.Time { return now })
	var names []string
	for i := range maxConcurrentIssuance + 1 {
		names = append(names, fmt.Sprintf("cert-%d", i))
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- r.RunDynamic(ctx, static(multiCfg(names...))) }()

	var running []*issueCall
	started := map[string]bool{}
	for range maxConcurrentIssuance {
		call := iss.next(t)
		running = append(running, call)
		started[call.spec.Name] = true
	}
	var queued string
	for _, name := range names {
		if !started[name] {
			queued = name
		}
	}

	cancel()
	select {
	case err := <-done:
		t.Fatalf("RunDynamic returned %v with issuances in flight", err)
	case <-time.After(100 * time.Millisecond):
	}
	for _, call := range running {
		call.succeed()
	}
	if err := receive(t, done, "RunDynamic"); !errors.Is(err, context.Canceled) {
		t.Fatalf("RunDynamic returned %v, want context.Canceled", err)
	}

	for name := range started {
		if _, err := db.Certs.Get(context.Background(), name, nil); err != nil {
			t.Fatalf("certificate %s issued before shutdown was not stored: %v", name, err)
		}
		assertStatus(t, db, store.IssuanceStatus{Name: name, LastAttemptAt: now})
	}
	assertNoCert(t, db, queued)
	if r.Issuing(queued) {
		t.Fatalf("queued issuance of %s still holds its lock", queued)
	}
}

// ---------------------------------------------------------------------------
// Reload
// ---------------------------------------------------------------------------

// ④ Publishing a configuration does not wait for a running issuance.
func TestPublishConfigDoesNotWaitForIssuance(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	oldCfg := minimalCfg("api-prod", 30, nil)
	newCfg := minimalCfg("api-prod", 30, nil)
	newCfg.Certificates[0].Domains = []string{"new.example.com"}
	iss := newGatedIssuer(now.Add(90 * 24 * time.Hour))
	r := New(iss, db.Certs, db.Issuance, nil, func() time.Time { return now })
	var current atomic.Pointer[config.ServerConfig]
	current.Store(oldCfg)

	if _, err := r.tick(ctx, current.Load); err != nil {
		t.Fatal(err)
	}
	call := iss.next(t)

	published := make(chan error, 1)
	go func() { published <- r.PublishConfig(ctx, func() { current.Store(newCfg) }) }()
	select {
	case err := <-published:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("PublishConfig waited for the in-flight issuance")
	}
	if current.Load() != newCfg {
		t.Fatal("new generation was not published")
	}
	call.succeed()
	r.wg.Wait()
}

// ⑤ A result obtained for a specification that a reload replaced is neither
// stored nor counted as a success, and the scheduler issues again under the
// new configuration.
func TestReloadedSpecDiscardsInFlightResult(t *testing.T) {
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	oldCfg := minimalCfg("api-prod", 30, nil)
	newCfg := minimalCfg("api-prod", 30, nil)
	newCfg.Certificates[0].Domains = []string{"new.example.com"}
	iss := newGatedIssuer(now.Add(90 * 24 * time.Hour))
	r := New(iss, db.Certs, db.Issuance, nil, func() time.Time { return now })
	var current atomic.Pointer[config.ServerConfig]
	current.Store(oldCfg)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- r.RunDynamic(ctx, current.Load) }()

	stale := iss.next(t)
	if stale.cfg != oldCfg {
		t.Fatal("first issuance did not use the running configuration")
	}
	if err := r.PublishConfig(context.Background(), func() { current.Store(newCfg) }); err != nil {
		t.Fatal(err)
	}
	stale.succeed()

	fresh := iss.next(t)
	if fresh.cfg != newCfg || !slices.Equal(fresh.spec.Domains, []string{"new.example.com"}) {
		t.Fatalf("reissue used domains %v, want the reloaded configuration", fresh.spec.Domains)
	}
	assertNoCert(t, db, "api-prod")
	assertNoStatus(t, db, "api-prod")

	fresh.succeed()
	cancel()
	if err := receive(t, done, "RunDynamic"); !errors.Is(err, context.Canceled) {
		t.Fatalf("RunDynamic returned %v", err)
	}
	rec, err := db.Certs.Get(context.Background(), "api-prod", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec.SpecFingerprint != config.CertificateSpecFingerprint(newCfg, newCfg.Certificates[0]) ||
		!slices.Equal(rec.Domains, []string{"new.example.com"}) {
		t.Fatalf("stored record = %+v, want the reloaded specification", rec)
	}
}

// ⑥ A result for a certificate removed during issuance is discarded.
func TestRemovedCertificateDiscardsInFlightResult(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	iss := newGatedIssuer(now.Add(90 * 24 * time.Hour))
	notifier := &recordingNotifier{}
	r := New(iss, db.Certs, db.Issuance, notifier, func() time.Time { return now })
	var current atomic.Pointer[config.ServerConfig]
	current.Store(minimalCfg("api-prod", 30, []string{"web-1"}))

	renewed := renewAsync(ctx, r, current.Load, "api-prod")
	call := iss.next(t)
	if err := r.PublishConfig(ctx, func() { current.Store(&config.ServerConfig{}) }); err != nil {
		t.Fatal(err)
	}
	call.succeed()

	err := receive(t, renewed, "RenewNamed")
	if err == nil || !strings.Contains(err.Error(), "discarded") {
		t.Fatalf("RenewNamed error = %v, want the result to be discarded", err)
	}
	assertNoCert(t, db, "api-prod")
	assertNoStatus(t, db, "api-prod")
	if calls := notifier.Calls(); len(calls) != 0 {
		t.Fatalf("discarded certificate was pushed: %v", calls)
	}
}

// ⑦ A reload that changes only the subscribers keeps the result, and push
// goes to the new subscribers.
func TestSubscriberOnlyReloadKeepsInFlightResult(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	oldCfg := minimalCfg("api-prod", 30, []string{"web-1"})
	newCfg := minimalCfg("api-prod", 30, []string{"web-2"})
	iss := newGatedIssuer(now.Add(90 * 24 * time.Hour))
	notifier := &recordingNotifier{}
	r := New(iss, db.Certs, db.Issuance, notifier, func() time.Time { return now })
	var current atomic.Pointer[config.ServerConfig]
	current.Store(oldCfg)

	renewed := renewAsync(ctx, r, current.Load, "api-prod")
	call := iss.next(t)
	if err := r.PublishConfig(ctx, func() { current.Store(newCfg) }); err != nil {
		t.Fatal(err)
	}
	call.succeed()
	if err := receive(t, renewed, "RenewNamed"); err != nil {
		t.Fatal(err)
	}

	rec, err := db.Certs.Get(ctx, "api-prod", nil)
	if err != nil {
		t.Fatalf("certificate was not stored: %v", err)
	}
	if rec.SpecFingerprint != config.CertificateSpecFingerprint(newCfg, newCfg.Certificates[0]) {
		t.Fatal("stored certificate does not match the running specification")
	}
	if calls := notifier.Calls(); !slices.Equal(calls, []notifyCall{{"web-2", "api-prod"}}) || notifier.cfg != newCfg {
		t.Fatalf("push calls = %v, want only the reloaded subscriber", calls)
	}
}

// ⑧ A failure under a replaced generation stores no backoff: the reload may
// have fixed what failed, so the certificate is issued again right away.
func TestOldGenerationFailureDoesNotBackOff(t *testing.T) {
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	oldCfg := minimalCfg("api-prod", 30, nil)
	// DNS credentials and the account email are not part of the fingerprint.
	newCfg := minimalCfg("api-prod", 30, nil)
	newCfg.ACME.Email = "ops@example.com"
	iss := newGatedIssuer(now.Add(90 * 24 * time.Hour))
	r := New(iss, db.Certs, db.Issuance, nil, func() time.Time { return now })
	var current atomic.Pointer[config.ServerConfig]
	current.Store(oldCfg)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- r.RunDynamic(ctx, current.Load) }()

	stale := iss.next(t)
	if err := r.PublishConfig(context.Background(), func() { current.Store(newCfg) }); err != nil {
		t.Fatal(err)
	}
	stale.fail(errors.New("dns credentials rejected"))

	retry := iss.next(t)
	if retry.cfg != newCfg {
		t.Fatal("retry did not use the reloaded configuration")
	}
	assertNoStatus(t, db, "api-prod")
	retry.succeed()
	cancel()
	if err := receive(t, done, "RunDynamic"); !errors.Is(err, context.Canceled) {
		t.Fatalf("RunDynamic returned %v", err)
	}
}

// ⑫ Publishing a configuration clears every backoff but keeps the last
// error, and wakes the scheduler.
func TestPublishConfigClearsBackoffAndWakes(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, name := range []string{"api-prod", "removed"} {
		if err := db.Issuance.Upsert(ctx, &store.IssuanceStatus{
			Name: name, Failures: 3, LastError: "dns timeout",
			LastAttemptAt: now.Add(-time.Hour), NextAttemptAt: now.Add(24 * time.Hour),
		}, nil); err != nil {
			t.Fatal(err)
		}
	}
	mi := &mockIssuer{result: successResult(now.Add(90 * 24 * time.Hour))}
	r := New(mi, db.Certs, db.Issuance, nil, func() time.Time { return now })
	oldCfg := minimalCfg("api-prod", 30, []string{"web-1"})
	newCfg := minimalCfg("api-prod", 30, []string{"web-2"})
	var current atomic.Pointer[config.ServerConfig]
	current.Store(oldCfg)

	if err := r.PublishConfig(ctx, func() { current.Store(newCfg) }); err != nil {
		t.Fatal(err)
	}
	if current.Load() != newCfg {
		t.Fatal("new generation was not published")
	}
	for _, name := range []string{"api-prod", "removed"} {
		st := mustStatus(t, db, name)
		if st.Failures != 0 || !st.NextAttemptAt.IsZero() {
			t.Fatalf("backoff of %s was not cleared: %+v", name, st)
		}
		if st.LastError != "dns timeout" || !st.LastAttemptAt.Equal(now.Add(-time.Hour)) {
			t.Fatalf("last attempt of %s was not kept: %+v", name, st)
		}
	}
	select {
	case <-r.wake:
	default:
		t.Fatal("PublishConfig did not wake the scheduler")
	}
	// The woken tick retries at once.
	if err := tickAndWait(ctx, r, current.Load()); err != nil {
		t.Fatal(err)
	}
	if mi.calls != 1 || mi.cfg != newCfg {
		t.Fatalf("Issue calls = %d with config %p, want 1 with %p", mi.calls, mi.cfg, newCfg)
	}
}

func TestPublishConfigKeepsGenerationWhenClearingBackoffFails(t *testing.T) {
	db := mustOpenDB(t)
	r := New(&mockIssuer{}, db.Certs, db.Issuance, nil, nil)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	published := false
	if err := r.PublishConfig(context.Background(), func() { published = true }); err == nil {
		t.Fatal("PublishConfig succeeded although the backoff could not be cleared")
	}
	if published {
		t.Fatal("configuration was published although the backoff could not be cleared")
	}
}

// ---------------------------------------------------------------------------
// Manual renewal
// ---------------------------------------------------------------------------

// ⑬ A manual renewal ignores expiry and backoff, and clears the backoff.
func TestRenewNamedIgnoresBackoff(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	mi := &mockIssuer{result: successResult(now.Add(120 * 24 * time.Hour))}
	r := New(mi, db.Certs, db.Issuance, nil, func() time.Time { return now })
	cfg := minimalCfg("api-prod", 30, nil)
	spec := cfg.Certificates[0]
	if err := db.Certs.Upsert(ctx, &store.CertRecord{
		Name: "api-prod", CA: "le", Domains: spec.Domains,
		SpecFingerprint: config.CertificateSpecFingerprint(cfg, spec),
		NotAfter:        now.Add(90 * 24 * time.Hour), UpdatedAt: now,
	}, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Issuance.Upsert(ctx, &store.IssuanceStatus{
		Name: "api-prod", Failures: 2, LastError: "CA down",
		LastAttemptAt: now.Add(-time.Minute), NextAttemptAt: now.Add(time.Hour),
	}, nil); err != nil {
		t.Fatal(err)
	}

	if err := r.RenewNamed(ctx, static(cfg), "api-prod"); err != nil {
		t.Fatalf("RenewNamed: %v", err)
	}
	if mi.calls != 1 {
		t.Fatalf("Issue calls = %d, want 1", mi.calls)
	}
	rec, err := db.Certs.Get(ctx, spec.Name, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec.FullchainPEM != "---cert---" || !rec.IssuedAt.Equal(now) {
		t.Fatalf("stored record = %+v", rec)
	}
	assertStatus(t, db, store.IssuanceStatus{Name: "api-prod", LastAttemptAt: now})
}

// ⑬ A manual renewal waiting for its certificate's lock or for a slot gives up
// as soon as ctx is cancelled, without issuing.
func TestRenewNamedStopsWaitingWhenCancelled(t *testing.T) {
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("certificate lock", func(t *testing.T) {
		ctx := context.Background()
		db := mustOpenDB(t)
		iss := newGatedIssuer(now.Add(90 * 24 * time.Hour))
		r := New(iss, db.Certs, db.Issuance, nil, func() time.Time { return now })
		current := static(minimalCfg("api-prod", 30, nil))

		holder := renewAsync(ctx, r, current, "api-prod")
		held := iss.next(t)
		waitCtx, cancelWait := context.WithCancel(ctx)
		waiting := renewAsync(waitCtx, r, current, "api-prod")
		iss.none(t)
		cancelWait()
		if err := receive(t, waiting, "cancelled RenewNamed"); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled RenewNamed = %v, want context.Canceled", err)
		}

		held.succeed()
		if err := receive(t, holder, "RenewNamed"); err != nil {
			t.Fatal(err)
		}
		iss.none(t)
	})

	t.Run("issuance slot", func(t *testing.T) {
		ctx := context.Background()
		db := mustOpenDB(t)
		iss := newGatedIssuer(now.Add(90 * 24 * time.Hour))
		r := New(iss, db.Certs, db.Issuance, nil, func() time.Time { return now })
		var busy []string
		for i := range maxConcurrentIssuance {
			busy = append(busy, fmt.Sprintf("busy-%d", i))
		}
		current := static(multiCfg(append(busy, "api-prod")...))

		var holders []<-chan error
		var running []*issueCall
		for _, name := range busy {
			holders = append(holders, renewAsync(ctx, r, current, name))
			running = append(running, iss.next(t))
		}
		waitCtx, cancelWait := context.WithCancel(ctx)
		waiting := renewAsync(waitCtx, r, current, "api-prod")
		waitFor(t, "api-prod waits for a slot", func() bool { return r.Issuing("api-prod") })
		iss.none(t)
		cancelWait()
		if err := receive(t, waiting, "cancelled RenewNamed"); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled RenewNamed = %v, want context.Canceled", err)
		}
		if r.Issuing("api-prod") {
			t.Fatal("cancelled renewal still holds its certificate lock")
		}

		for i, call := range running {
			call.succeed()
			if err := receive(t, holders[i], "RenewNamed"); err != nil {
				t.Fatal(err)
			}
		}
		iss.none(t)
		assertNoCert(t, db, "api-prod")
	})
}

func TestRenewNamedRenewsOnlyTheExactName(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	mi := &mockIssuer{result: successResult(now.Add(90 * 24 * time.Hour))}
	r := New(mi, db.Certs, db.Issuance, nil, func() time.Time { return now })
	cfg := minimalCfg("api-prod", 30, nil)
	stage := cfg.Certificates[0]
	stage.Name = "api-stage"
	cfg.Certificates = append(cfg.Certificates, stage)
	current := static(cfg)

	if err := r.RenewNamed(ctx, current, "api-prod"); err != nil {
		t.Fatalf("RenewNamed: %v", err)
	}
	if mi.calls != 1 || mi.cfg != cfg {
		t.Fatalf("Issue calls = %d with config %p, want 1 call with the live snapshot %p", mi.calls, mi.cfg, cfg)
	}
	if _, err := db.Certs.Get(ctx, "api-prod", nil); err != nil {
		t.Fatalf("renewed certificate was not stored: %v", err)
	}
	assertNoCert(t, db, "api-stage")

	err := r.RenewNamed(ctx, current, "API-PROD")
	if err == nil || !strings.Contains(err.Error(), `cert "API-PROD" not found`) {
		t.Fatalf("case-mismatched name error = %v", err)
	}
	if mi.calls != 1 {
		t.Fatalf("unknown name triggered issuance; calls = %d", mi.calls)
	}
	if r.Issuing("API-PROD") || len(r.locks) != 1 {
		t.Fatalf("unknown name created a certificate lock: %v", r.locks)
	}
}

func TestRenewNamedPropagatesIssuerFailure(t *testing.T) {
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	want := errors.New("acme failed\x1b[2J")
	r := New(&mockIssuer{err: want}, db.Certs, db.Issuance, nil, func() time.Time { return now })
	cfg := minimalCfg("api-prod", 30, nil)
	err := r.RenewNamed(context.Background(), static(cfg), "api-prod")
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	assertStatus(t, db, store.IssuanceStatus{
		Name: "api-prod", Failures: 1, LastError: "acme failed [2J",
		LastAttemptAt: now, NextAttemptAt: now.Add(baseBackoff),
	})
}

func TestRenewNamedReportsStoreFailure(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	iss := newGatedIssuer(now.Add(90 * 24 * time.Hour))
	notifier := &recordingNotifier{}
	r := New(iss, db.Certs, db.Issuance, notifier, func() time.Time { return now })

	renewed := renewAsync(ctx, r, static(minimalCfg("api-prod", 30, []string{"web-1"})), "api-prod")
	call := iss.next(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	call.succeed()
	if err := receive(t, renewed, "RenewNamed"); err == nil || !strings.Contains(err.Error(), "upsert cert") {
		t.Fatalf("RenewNamed error = %v, want the store failure", err)
	}
	if calls := notifier.Calls(); len(calls) != 0 {
		t.Fatalf("unstored certificate was pushed: %v", calls)
	}
}

// ---------------------------------------------------------------------------
// Backoff
// ---------------------------------------------------------------------------

// ⑩ TestTick_FailureBackoff: each failure is stored and doubles the delay
// before the next tick may retry.
func TestTick_FailureBackoff(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := now
	mi := &mockIssuer{err: errors.New("ACME unavailable")}
	r := New(mi, db.Certs, db.Issuance, nil, func() time.Time { return clock })
	cfg := minimalCfg("api-prod", 30, nil)

	for failures, delay := range []time.Duration{5 * time.Minute, 10 * time.Minute, 20 * time.Minute} {
		if err := tickAndWait(ctx, r, cfg); err != nil {
			t.Fatal(err)
		}
		if mi.calls != failures+1 {
			t.Fatalf("Issue calls = %d, want %d", mi.calls, failures+1)
		}
		want := store.IssuanceStatus{
			Name: "api-prod", Failures: failures + 1, LastError: "ACME unavailable",
			LastAttemptAt: clock, NextAttemptAt: clock.Add(delay),
		}
		assertStatus(t, db, want)

		// Still in backoff one second before the retry time.
		clock = want.NextAttemptAt.Add(-time.Second)
		if err := tickAndWait(ctx, r, cfg); err != nil {
			t.Fatal(err)
		}
		if mi.calls != failures+1 {
			t.Fatalf("tick in backoff issued; calls = %d", mi.calls)
		}
		clock = want.NextAttemptAt
	}
}

// ⑩ The delay doubles from baseBackoff and is capped at maxBackoff.
func TestRetryDelay(t *testing.T) {
	for _, tc := range []struct {
		failures int
		want     time.Duration
	}{
		{1, 5 * time.Minute},
		{2, 10 * time.Minute},
		{3, 20 * time.Minute},
		{4, 40 * time.Minute},
		{9, 1280 * time.Minute},
		{10, maxBackoff},
		{1000, maxBackoff},
	} {
		if got := retryDelay(tc.failures); got != tc.want {
			t.Errorf("retryDelay(%d) = %v, want %v", tc.failures, got, tc.want)
		}
	}
}

// ⑨ The backoff is stored, so a restarted scheduler keeps honoring it.
func TestBackoffSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := minimalCfg("api-prod", 30, nil)
	failing := New(&mockIssuer{err: errors.New("CA down")}, db.Certs, db.Issuance, nil, func() time.Time { return now })
	if err := tickAndWait(ctx, failing, cfg); err != nil {
		t.Fatal(err)
	}

	clock := now.Add(baseBackoff - time.Second)
	mi := &mockIssuer{result: successResult(now.Add(90 * 24 * time.Hour))}
	restarted := New(mi, db.Certs, db.Issuance, nil, func() time.Time { return clock })
	if err := tickAndWait(ctx, restarted, cfg); err != nil {
		t.Fatal(err)
	}
	if mi.calls != 0 {
		t.Fatalf("restarted scheduler retried %d times during the backoff", mi.calls)
	}
	clock = now.Add(baseBackoff)
	if err := tickAndWait(ctx, restarted, cfg); err != nil {
		t.Fatal(err)
	}
	if mi.calls != 1 {
		t.Fatalf("restarted scheduler did not retry after the backoff; calls = %d", mi.calls)
	}
}

// ⑪ TestTick_SuccessClearsBackoff: success resets failures, error and retry time.
func TestTick_SuccessClearsBackoff(t *testing.T) {
	ctx := context.Background()
	db := mustOpenDB(t)
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := db.Issuance.Upsert(ctx, &store.IssuanceStatus{
		Name: "api-prod", Failures: 3, LastError: "fail",
		LastAttemptAt: now.Add(-time.Hour), NextAttemptAt: now.Add(-time.Minute),
	}, nil); err != nil {
		t.Fatal(err)
	}
	mi := &mockIssuer{result: successResult(now.Add(90 * 24 * time.Hour))}
	r := New(mi, db.Certs, db.Issuance, nil, func() time.Time { return now })

	if err := tickAndWait(ctx, r, minimalCfg("api-prod", 30, nil)); err != nil {
		t.Fatal(err)
	}
	if mi.calls != 1 {
		t.Fatalf("Issue calls = %d, want 1", mi.calls)
	}
	assertStatus(t, db, store.IssuanceStatus{Name: "api-prod", LastAttemptAt: now})
}

// The stored error quotes CA and DNS API responses that the CLI prints to a
// terminal.
func TestLastErrorIsSanitized(t *testing.T) {
	// An odd-length prefix puts the cut in the middle of a two-byte character.
	prefix := "acme: 400 \x1b[31mbad\x1b[0m\r\nretry\u009b\x7f!!"
	got := lastError(errors.New(prefix + strings.Repeat("é", maxLastErrorBytes)))

	if want := "acme: 400  [31mbad [0m  retry  !!"; !strings.HasPrefix(got, want) {
		t.Fatalf("lastError = %q, want prefix %q", got, want)
	}
	if len(got) > maxLastErrorBytes || len(got) <= maxLastErrorBytes-utf8.UTFMax {
		t.Fatalf("lastError is %d bytes, want at most %d", len(got), maxLastErrorBytes)
	}
	if !utf8.ValidString(got) {
		t.Fatal("lastError split a character")
	}
	if i := strings.IndexFunc(got, unicode.IsControl); i >= 0 {
		t.Fatalf("lastError keeps control character %q", got[i:i+1])
	}
	if got := lastError(errors.New("short")); got != "short" {
		t.Fatalf("lastError(short) = %q", got)
	}
}

// TestNoopNotifier: NoopNotifier returns no error.
func TestNoopNotifier(t *testing.T) {
	n := NoopNotifier()
	if err := n.Notify(context.Background(), &config.ServerConfig{}, "client", "cert"); err != nil {
		t.Errorf("NoopNotifier.Notify returned error: %v", err)
	}
}
