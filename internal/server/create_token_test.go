package server

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/ca"
	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/enroll"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

// TestCreateTokenRequiresAHostClientsCanReach covers a configuration without
// public_url, where the URL a token is bound to comes from server.listen.
func TestCreateTokenRequiresAHostClientsCanReach(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	miniCA, err := ca.Bootstrap(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	enrollSrv := enroll.NewServer(db.Tokens, db.Clients, miniCA)
	ctx := context.Background()

	tests := []struct {
		listen, publicURL string
		wantURL           string // empty when the token must be refused
	}{
		{listen: ":8443"},
		{listen: "0.0.0.0:8443"},
		{listen: "[::]:8443"},
		{listen: "127.0.0.1:8443", wantURL: "https://127.0.0.1:8443"},
		{listen: "sigil.internal:8443", wantURL: "https://sigil.internal:8443"},
		{listen: ":8443", publicURL: "https://sigil.example.com", wantURL: "https://sigil.example.com"},
	}
	for i, tt := range tests {
		cfg := &config.ServerConfig{Server: config.ServerSection{Listen: tt.listen, PublicURL: tt.publicURL}}
		resp, err := createToken(ctx, enrollSrv, cfg, fmt.Sprintf("web-%d", i), time.Hour)
		if tt.wantURL == "" {
			want := fmt.Sprintf("server.public_url must be set: server.listen %q names no host clients can reach", tt.listen)
			if err == nil || err.Error() != want {
				t.Errorf("listen %q: error = %v, want %q", tt.listen, err, want)
			}
			continue
		}
		if err != nil {
			t.Errorf("listen %q, public_url %q: %v", tt.listen, tt.publicURL, err)
			continue
		}
		if resp.ServerURL != tt.wantURL {
			t.Errorf("listen %q, public_url %q: token bound to %q, want %q", tt.listen, tt.publicURL, resp.ServerURL, tt.wantURL)
		}
	}

	// A refused token is not stored.
	tokens, err := db.Tokens.List(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 3 {
		t.Fatalf("stored %d tokens, want only the 3 accepted ones", len(tokens))
	}
}
