package commands

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

// longName is a client name of the greatest length ValidateClientName
// accepts.
var longName = strings.Repeat("a", 63)

// tableCells splits each line of table, the header and its rows, where the
// header's columns start, and trims the spaces around each cell. A row whose
// cells do not start where the header's columns do splits into cells that
// are not its values.
func tableCells(t *testing.T, table string, columns ...string) [][]string {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(table, "\n"), "\n")
	starts := make([]int, len(columns))
	for i, column := range columns {
		starts[i] = strings.Index(lines[0], column)
		if starts[i] < 0 || (i > 0 && starts[i] <= starts[i-1]) {
			t.Fatalf("header %q does not hold %q in order", lines[0], columns)
		}
	}
	cells := make([][]string, 0, len(lines))
	for _, line := range lines {
		row := make([]string, len(columns))
		for i, start := range starts {
			end := len(line)
			if i+1 < len(starts) {
				end = min(starts[i+1], len(line))
			}
			row[i] = strings.TrimSpace(line[min(start, end):end])
		}
		cells = append(cells, row)
	}
	return cells
}

// TestTokenListAlignsColumns covers sigils token list with token IDs of 32
// characters and a name of 63: every row starts its cells where the header
// starts its columns.
func TestTokenListAlignsColumns(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(time.Hour)
	tokens := []*store.TokenRecord{
		// The list shows the newest first.
		{TokenID: "0123456789abcdef0123456789abcdef", Name: "web-1", ExpiresAt: expires, CreatedAt: now},
		{TokenID: "fedcba9876543210fedcba9876543210", Name: longName, ExpiresAt: expires, CreatedAt: now.Add(-time.Minute), UsedAt: now},
	}
	for _, tok := range tokens {
		if err := db.Tokens.Upsert(context.Background(), tok, nil); err != nil {
			t.Fatal(err)
		}
	}
	// serveCertificates serves the tokens of db as well.
	socket := serveCertificates(t, db, &config.ServerConfig{})

	table := runSigils(t, "--ipc", socket, "token", "list")
	got := tableCells(t, table, "ID", "NAME", "STATUS", "EXPIRES")
	want := [][]string{
		{"ID", "NAME", "STATUS", "EXPIRES"},
		{tokens[0].TokenID, "web-1", "unused", expires.Format("2006-01-02 15:04")},
		{tokens[1].TokenID, longName, "used", expires.Format("2006-01-02 15:04")},
	}
	if !slices.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("token list does not line up with its header:\n%s", table)
	}
}

// TestTokenListShowsExpiredTokens covers a token that expired unused. The
// store lists every token, and the TUI shows this one as expired; the CLI
// must not offer it as unused, since enrolling with it fails.
func TestTokenListShowsExpiredTokens(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now().UTC().Truncate(time.Second)
	expired := &store.TokenRecord{
		TokenID: "0123456789abcdef0123456789abcdef", Name: "web-1",
		ExpiresAt: now.Add(-time.Minute), CreatedAt: now.Add(-time.Hour),
	}
	if err := db.Tokens.Upsert(context.Background(), expired, nil); err != nil {
		t.Fatal(err)
	}
	socket := serveCertificates(t, db, &config.ServerConfig{})

	table := runSigils(t, "--ipc", socket, "token", "list")
	got := tableCells(t, table, "ID", "NAME", "STATUS", "EXPIRES")
	if len(got) != 2 || got[1][2] != "expired" {
		t.Fatalf("token list does not show the expired token as expired:\n%s", table)
	}
}

// TestClientListAlignsColumns covers sigils client list with a name of 63
// characters and fingerprints of 71: every row starts its cells where the
// header starts its columns.
func TestClientListAlignsColumns(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now().UTC().Truncate(time.Second)
	clients := []*store.ClientRecord{
		// The list is in name order.
		{Name: longName, Fingerprint: "sha256:" + strings.Repeat("ab", 32), EnrolledAt: now},
		{Name: "web-1", Fingerprint: "sha256:" + strings.Repeat("cd", 32), EnrolledAt: now, LastSeen: now},
	}
	for _, cl := range clients {
		if err := db.Clients.Upsert(context.Background(), cl, nil); err != nil {
			t.Fatal(err)
		}
	}
	// serveCertificates serves the clients of db as well.
	socket := serveCertificates(t, db, &config.ServerConfig{})

	table := runSigils(t, "--ipc", socket, "client", "list")
	got := tableCells(t, table, "NAME", "FINGERPRINT", "LAST SEEN")
	want := [][]string{
		{"NAME", "FINGERPRINT", "LAST SEEN"},
		{longName, clients[0].Fingerprint, "never"},
		{"web-1", clients[1].Fingerprint, now.Format("2006-01-02 15:04")},
	}
	if !slices.EqualFunc(got, want, slices.Equal) {
		t.Fatalf("client list does not line up with its header:\n%s", table)
	}
}
