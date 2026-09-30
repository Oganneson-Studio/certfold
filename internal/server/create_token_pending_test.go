package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/ca"
	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/enroll"
	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

// TestCreateTokenRequiresReplaceForANamePendingEnrollment covers tokens
// created for a batch of hosts before any of them installs, with one name
// typed twice. Neither name is enrolled yet, so the enrolled-client check
// passes both; the host that redeems the second token after the first
// replaces the client the first created, and takes its certificates, which
// is what --replace exists to prevent. A name with an unused token that has
// not expired needs --replace as an enrolled one does.
//
// A replacement revokes the unused tokens of the name: otherwise the host of
// an old token, enrolling after the host of the new one, would replace it.
func TestCreateTokenRequiresReplaceForANamePendingEnrollment(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	miniCA, err := ca.Bootstrap(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	enrollSrv := enroll.NewServer(db, miniCA)
	cfg := &config.ServerConfig{Server: config.ServerSection{PublicURL: "https://sigil.example.com"}}
	ctx := context.Background()

	first, err := createToken(ctx, enrollSrv, db, cfg, ipc.CreateTokenRequest{Name: "web-1", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	_, err = createToken(ctx, enrollSrv, db, cfg, ipc.CreateTokenRequest{Name: "web-1", TTL: time.Hour})
	if !errors.Is(err, ipc.ErrReplaceRequired) {
		t.Fatalf("second token for web-1 while the first is unused: error = %v, want one that asks for a replacement", err)
	}
	// A token that has expired unused, or has been used by a client since
	// removed, enrolls no host, and needs no replacement. A token created
	// without replace revokes neither, and a replacement leaves the used
	// one alone.
	now := time.Now()
	for _, tok := range []*store.TokenRecord{
		{TokenID: "0123456789abcdef0123456789abcdef", Name: "web-2", ExpiresAt: now.Add(-time.Minute), CreatedAt: now.Add(-time.Hour)},
		{TokenID: "fedcba9876543210fedcba9876543210", Name: "web-3", ExpiresAt: now.Add(time.Hour), CreatedAt: now.Add(-time.Hour), UsedAt: now},
	} {
		if err := db.Tokens.Upsert(ctx, tok, nil); err != nil {
			t.Fatal(err)
		}
		resp, err := createToken(ctx, enrollSrv, db, cfg, ipc.CreateTokenRequest{Name: tok.Name, TTL: time.Hour})
		if err != nil {
			t.Fatalf("token for %s, whose other token enrolls no host: %v", tok.Name, err)
		}
		if resp.Revoked != 0 {
			t.Errorf("token for %s without replace revoked %d tokens", tok.Name, resp.Revoked)
		}
		if _, err := db.Tokens.Get(ctx, tok.TokenID, nil); err != nil {
			t.Errorf("token for %s without replace deleted token %s: %v", tok.Name, tok.TokenID, err)
		}
	}
	if resp, err := createToken(ctx, enrollSrv, db, cfg, ipc.CreateTokenRequest{Name: "web-3", TTL: time.Hour, Replace: true}); err != nil || resp.Revoked != 1 {
		t.Fatalf("replacing token for web-3: revoked %d, error %v; want the one unused token revoked", resp.Revoked, err)
	}
	if _, err := db.Tokens.Get(ctx, "fedcba9876543210fedcba9876543210", nil); err != nil {
		t.Errorf("the replacement revoked the used token of web-3: %v", err)
	}

	second, err := createToken(ctx, enrollSrv, db, cfg, ipc.CreateTokenRequest{Name: "web-1", TTL: time.Hour, Replace: true})
	if err != nil {
		t.Fatalf("second token for web-1 with --replace: %v", err)
	}
	if second.Revoked != 1 {
		t.Errorf("the replacement revoked %d tokens, want 1", second.Revoked)
	}
	if _, _, err := enrollSrv.Verify(ctx, first.Token); err == nil {
		t.Error("the unused token the replacement revoked still redeems")
	}
	if name, _, err := enrollSrv.Verify(ctx, second.Token); err != nil || name != "web-1" {
		t.Errorf("the replacing token: name %q, error %v; want web-1", name, err)
	}
}
