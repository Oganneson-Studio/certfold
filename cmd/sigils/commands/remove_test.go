package commands

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

// TestRemoveReportsMissingClientOrToken covers sigils client remove and token
// revoke. For a name or ID that does not exist, such as a mistyped one, the
// command fails with the reason of the daemon, which main prints before it
// exits 1, instead of reporting a removal that did not happen. For one that
// exists, it reports the removal.
func TestRemoveReportsMissingClientOrToken(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now()
	if err := db.Clients.Upsert(ctx, &store.ClientRecord{Name: "web-1", Fingerprint: "sha256:AA", EnrolledAt: now}, nil); err != nil {
		t.Fatal(err)
	}
	tokenID := "0123456789abcdef0123456789abcdef"
	if err := db.Tokens.Upsert(ctx, &store.TokenRecord{
		TokenID:   tokenID,
		Name:      "web-2",
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}, nil); err != nil {
		t.Fatal(err)
	}
	// serveCertificates serves the clients and tokens of db as well.
	socket := serveCertificates(t, db, &config.ServerConfig{})

	missingToken := strings.Repeat("0", 32)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"client", "remove", "web-9"}, `server returned 404: client "web-9" is not enrolled`},
		{[]string{"token", "revoke", missingToken}, `server returned 404: enrollment token "` + missingToken + `" does not exist`},
	} {
		root := NewRootCmd()
		root.SetArgs(append([]string{"--ipc", socket}, tc.args...))
		if err := root.Execute(); err == nil || !strings.HasSuffix(err.Error(), tc.want) {
			t.Errorf("sigils %s: error = %v, want it to end in %s", strings.Join(tc.args, " "), err, tc.want)
		}
	}

	if got, want := runSigils(t, "--ipc", socket, "client", "remove", "web-1"), "client \"web-1\" removed\n"; got != want {
		t.Errorf("client remove web-1 printed %q, want %q", got, want)
	}
	if got, want := runSigils(t, "--ipc", socket, "token", "revoke", tokenID), "token \""+tokenID+"\" revoked\n"; got != want {
		t.Errorf("token revoke printed %q, want %q", got, want)
	}
	if _, err := db.Clients.Get(ctx, "web-1", nil); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("Get of the removed client: error = %v, want sql.ErrNoRows", err)
	}
	if _, err := db.Tokens.Get(ctx, tokenID, nil); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("Get of the revoked token: error = %v, want sql.ErrNoRows", err)
	}
}
