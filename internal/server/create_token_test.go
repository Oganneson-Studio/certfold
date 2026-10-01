package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Oganneson-Studio/certfold/internal/ca"
	"github.com/Oganneson-Studio/certfold/internal/config"
	"github.com/Oganneson-Studio/certfold/internal/enroll"
	"github.com/Oganneson-Studio/certfold/internal/ipc"
	"github.com/Oganneson-Studio/certfold/internal/store"
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
	enrollSrv := enroll.NewServer(db, miniCA)
	ctx := context.Background()

	tests := []struct {
		listen, publicURL string
		wantURL           string // empty when the token must be refused
	}{
		{listen: ":8443"},
		{listen: "0.0.0.0:8443"},
		{listen: "[::]:8443"},
		{listen: "127.0.0.1:8443", wantURL: "https://127.0.0.1:8443"},
		{listen: "certfold.internal:8443", wantURL: "https://certfold.internal:8443"},
		{listen: ":8443", publicURL: "https://certfold.example.com", wantURL: "https://certfold.example.com"},
	}
	for i, tt := range tests {
		cfg := &config.ServerConfig{Server: config.ServerSection{Listen: tt.listen, PublicURL: tt.publicURL}}
		resp, err := createToken(ctx, enrollSrv, db, cfg, ipc.CreateTokenRequest{Name: fmt.Sprintf("web-%d", i), TTL: time.Hour})
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

// TestCreateTokenRequiresReplaceForAnEnrolledName covers `certfolds token create
// --name web-1` when web-1 is enrolled, such as a name mistyped as the name
// of another host: whoever redeems the token replaces that client, so the
// daemon issues it only when the request says to replace.
func TestCreateTokenRequiresReplaceForAnEnrolledName(t *testing.T) {
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
	cfg := &config.ServerConfig{Server: config.ServerSection{PublicURL: "https://certfold.example.com"}}
	ctx := context.Background()
	if err := db.Clients.Upsert(ctx, &store.ClientRecord{Name: "web-1", Fingerprint: "sha256:AA", EnrolledAt: time.Now()}, nil); err != nil {
		t.Fatal(err)
	}

	_, err = createToken(ctx, enrollSrv, db, cfg, ipc.CreateTokenRequest{Name: "web-1", TTL: time.Hour})
	if !errors.Is(err, ipc.ErrReplaceRequired) || !strings.Contains(err.Error(), `client "web-1" is already enrolled`) {
		t.Fatalf("token for an enrolled name: error = %v, want one that asks for a replacement", err)
	}
	if tokens, err := db.Tokens.List(ctx, nil); err != nil || len(tokens) != 0 {
		t.Fatalf("stored %d tokens for the refused name (err %v)", len(tokens), err)
	}

	for _, req := range []ipc.CreateTokenRequest{
		{Name: "web-1", TTL: time.Hour, Replace: true},
		{Name: "web-2", TTL: time.Hour},
	} {
		if _, err := createToken(ctx, enrollSrv, db, cfg, req); err != nil {
			t.Errorf("createToken(%+v): %v", req, err)
		}
	}
}
