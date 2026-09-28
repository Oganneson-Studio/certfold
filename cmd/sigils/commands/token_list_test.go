package commands

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

// TestTokenListAlignsColumns covers sigils token list: token IDs are 32 hex
// characters, and every row starts its columns where the header does.
func TestTokenListAlignsColumns(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now().UTC().Truncate(time.Second)
	names := map[string]string{
		"0123456789abcdef0123456789abcdef": "web-1",
		"fedcba9876543210fedcba9876543210": "db-primary",
	}
	for id, name := range names {
		if err := db.Tokens.Upsert(context.Background(), &store.TokenRecord{
			TokenID:   id,
			Name:      name,
			ExpiresAt: now.Add(time.Hour),
			CreatedAt: now,
		}, nil); err != nil {
			t.Fatal(err)
		}
	}
	// serveCertificates serves the tokens of db as well.
	socket := serveCertificates(t, db, &config.ServerConfig{})

	table := runSigils(t, "--ipc", socket, "token", "list")
	lines := strings.Split(strings.TrimSuffix(table, "\n"), "\n")
	if len(lines) != 1+len(names) {
		t.Fatalf("token list printed %d lines, want a header and %d rows:\n%s", len(lines), len(names), table)
	}
	header := lines[0]
	for _, line := range lines[1:] {
		id := strings.Fields(line)[0]
		want := map[string]string{"NAME": names[id], "STATUS": "unused", "EXPIRES": now.Add(time.Hour).Format("2006-01-02 15:04")}
		for column, value := range want {
			at := strings.Index(header, column)
			if at < 0 || len(line) < at+len(value) || line[at-1] != ' ' || line[at:at+len(value)] != value {
				t.Errorf("row %q does not have %s %q where the header has it:\n%s", line, column, value, table)
			}
		}
	}
}
