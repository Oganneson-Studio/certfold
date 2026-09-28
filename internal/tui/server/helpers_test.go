package server

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/logging"
)

// testToken stands in for an enrollment token. Real ones hold the mini-CA
// certificate, so they are about as long.
var testToken = strings.Repeat("eyJzZXJ2ZXJfdXJs", 66)

const testServerURL = "https://sigil.example.com:8443"

// fakeBackend serves lists and events from memory and records the calls
// that change state.
type fakeBackend struct {
	mu      sync.Mutex
	certs   []*ipc.CertificateInfo
	clients []*ipc.ClientInfo
	tokens  []*ipc.TokenInfo
	started time.Time
	events  []logging.Event
	// listErr fails every read and actionErr every change while set.
	listErr   error
	actionErr error
	calls     []string // the changes asked for, such as "DeleteClient web-1"
	afters    []uint64 // the after of each Events call
}

// newFake returns a fakeBackend with three certificates, clients and
// tokens, and events with Seq 1 to n.
func newFake(n uint64) *fakeBackend {
	now := time.Now()
	return &fakeBackend{
		certs: []*ipc.CertificateInfo{
			{
				Name: "api-prod", CA: "le", Domains: []string{"api.example.com", "www.example.com"},
				Subscribers: []string{"web-1", "web-2"}, State: ipc.CertStateValid, Fingerprint: "sha256:AA",
				IssuedAt: now.Add(-30 * 24 * time.Hour), NotAfter: now.Add(60 * 24 * time.Hour),
				RenewAt: now.Add(30 * 24 * time.Hour), RenewSource: "ratio",
			},
			{
				Name: "mail", CA: "le", Domains: []string{"mail.example.com"}, Subscribers: []string{"web-2"},
				State: ipc.CertStateBackoff, Failures: 2, LastError: "acme: rate limited",
				LastAttemptAt: now.Add(-5 * time.Minute), NextAttemptAt: now.Add(10 * time.Minute),
			},
			{Name: "new-cert", CA: "le", Domains: []string{"new.example.com"}, State: ipc.CertStatePending},
		},
		clients: []*ipc.ClientInfo{
			{Name: "web-1", Fingerprint: "sha256:01", EnrolledAt: now.Add(-48 * time.Hour), LastSeen: now.Add(-time.Minute)},
			{Name: "web-2", Fingerprint: "sha256:02", EnrolledAt: now.Add(-24 * time.Hour)},
			{Name: "web-3", Fingerprint: "sha256:03", EnrolledAt: now.Add(-time.Hour)},
		},
		// Newest first, as the daemon lists them.
		tokens: []*ipc.TokenInfo{
			{TokenID: "t3", Name: "web-6", ExpiresAt: now.Add(time.Hour), CreatedAt: now.Add(-time.Minute)},
			{TokenID: "t2", Name: "web-5", ExpiresAt: now.Add(time.Hour), UsedAt: now.Add(-time.Hour), CreatedAt: now.Add(-2 * time.Hour)},
			{TokenID: "t1", Name: "web-4", ExpiresAt: now.Add(-time.Hour), CreatedAt: now.Add(-3 * time.Hour)},
		},
		started: now.Add(-time.Hour),
		events:  makeEvents(1, n, "event"),
	}
}

// makeEvents returns events with Seq from to to, whose messages are prefix-Seq.
func makeEvents(from, to uint64, prefix string) []logging.Event {
	var events []logging.Event
	for seq := from; seq <= to; seq++ {
		events = append(events, logging.Event{
			Seq: seq, Time: time.Now(), Level: "INFO",
			Message: fmt.Sprintf("%s-%d", prefix, seq), Attrs: "cert=api-prod",
		})
	}
	return events
}

// restart makes the fake a daemon that started again and wrote events.
func (f *fakeBackend) restart(events []logging.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started = f.started.Add(time.Hour)
	f.events = events
}

func (f *fakeBackend) setEvents(events []logging.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = events
}

func (f *fakeBackend) setListErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listErr = err
}

func (f *fakeBackend) setActionErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.actionErr = err
}

func (f *fakeBackend) setClients(clients []*ipc.ClientInfo) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clients = clients
}

func (f *fakeBackend) changes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeBackend) eventsAfters() []uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uint64(nil), f.afters...)
}

func (f *fakeBackend) change(call string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
	return f.actionErr
}

func (f *fakeBackend) ListCerts(context.Context) ([]*ipc.CertificateInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.certs, f.listErr
}

func (f *fakeBackend) ListClients(context.Context) ([]*ipc.ClientInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.clients, f.listErr
}

func (f *fakeBackend) ListTokens(context.Context) ([]*ipc.TokenInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokens, f.listErr
}

func (f *fakeBackend) Events(_ context.Context, after uint64) (*ipc.EventsPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.afters = append(f.afters, after)
	if f.listErr != nil {
		return nil, f.listErr
	}
	page := &ipc.EventsPage{Started: f.started, Events: []logging.Event{}}
	for _, e := range f.events {
		if e.Seq > after {
			page.Events = append(page.Events, e)
		}
	}
	return page, nil
}

func (f *fakeBackend) RenewCert(_ context.Context, name string) error {
	return f.change("RenewCert " + name)
}

func (f *fakeBackend) DeleteClient(_ context.Context, name string) error {
	return f.change("DeleteClient " + name)
}

func (f *fakeBackend) DeleteToken(_ context.Context, id string) error {
	return f.change("DeleteToken " + id)
}

// CreateToken lists the new token first, as the daemon does.
func (f *fakeBackend) CreateToken(_ context.Context, req ipc.CreateTokenRequest) (*ipc.CreateTokenResponse, error) {
	if err := f.change(fmt.Sprintf("CreateToken %s %s", req.Name, req.TTL)); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	token := &ipc.TokenInfo{TokenID: fmt.Sprintf("t%d", len(f.tokens)+1), Name: req.Name, ExpiresAt: now.Add(req.TTL), CreatedAt: now}
	f.tokens = append([]*ipc.TokenInfo{token}, f.tokens...)
	return &ipc.CreateTokenResponse{Token: testToken, ServerURL: testServerURL, PublicURLConfigured: true}, nil
}

// drive sends msgs to m, then the messages of the commands Update returns,
// until no command is left. It reports whether a command quit. Tests never
// send tickMsg, whose command waits for the next refresh; every other
// command of the TUI returns at once.
func drive(t *testing.T, m Model, msgs ...tea.Msg) (Model, bool) {
	t.Helper()
	quit := false
	for len(msgs) > 0 {
		msg := msgs[0]
		msgs = msgs[1:]
		switch msg := msg.(type) {
		case tea.QuitMsg:
			quit = true
			continue
		case tea.BatchMsg:
			for _, cmd := range msg {
				if cmd != nil {
					msgs = append(msgs, cmd())
				}
			}
			continue
		}
		next, cmd := m.Update(msg)
		m = next.(Model)
		if cmd != nil {
			msgs = append(msgs, cmd())
		}
	}
	return m, quit
}

// press sends the keys to m, each a key name such as "enter" or text to type.
func press(t *testing.T, m Model, keys ...string) (Model, bool) {
	t.Helper()
	msgs := make([]tea.Msg, len(keys))
	for i, k := range keys {
		msgs[i] = keyMsg(k)
	}
	return drive(t, m, msgs...)
}

// refresh runs one refresh of m.
func refresh(t *testing.T, m Model) Model {
	t.Helper()
	m, _ = drive(t, m, m.load()())
	return m
}

// loaded returns a Model of 100 by 30 cells that shows what b serves.
func loaded(t *testing.T, b Backend) Model {
	t.Helper()
	m, _ := drive(t, New(b), tea.WindowSizeMsg{Width: 100, Height: 30})
	return refresh(t, m)
}

// onTab returns a Model loaded from b that shows tab, with each table's
// cursor on its second row and the Events view scrolled halfway, so that
// every move shows.
func onTab(t *testing.T, b Backend, tab int) Model {
	t.Helper()
	m := loaded(t, b)
	m.tab = tab
	m.certsTable.SetCursor(1)
	m.clientsTable.SetCursor(1)
	m.tokensTable.SetCursor(1)
	m, _ = drive(t, m, tea.WindowSizeMsg{Width: m.width, Height: m.height})
	m.eventsView.SetYOffset(m.eventsView.YOffset / 2)
	return m
}

// keyTypes maps the names of the special keys to their types.
var keyTypes = func() map[string]tea.KeyType {
	types := make(map[string]tea.KeyType)
	for t := tea.KeyType(-200); t < 200; t++ {
		if name := (tea.Key{Type: t}).String(); name != "" {
			types[name] = t
		}
	}
	return types
}()

// keyMsg returns the message of the key named k, as bubbletea names keys.
func keyMsg(k string) tea.KeyMsg {
	if k == " " {
		return tea.KeyMsg{Type: tea.KeySpace, Runes: []rune(k)}
	}
	if t, ok := keyTypes[k]; ok {
		return tea.KeyMsg{Type: t}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
}

// shows reports whether the view of m holds text, however it wraps.
func shows(m Model, text string) bool {
	return strings.Contains(strings.Join(strings.Fields(m.View()), " "), strings.Join(strings.Fields(text), " "))
}
