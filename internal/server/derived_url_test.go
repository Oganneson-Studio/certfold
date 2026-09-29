package server

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/ca"
	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/enroll"
	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

// Without public_url a token carries the URL derived from server.listen, and
// sigilc refuses one that could not be server.public_url. createToken
// refuses such a URL before it stores a token no client could redeem, and
// says what to set.
func TestCreateTokenRefusesADerivedURLSigilcWouldRefuse(t *testing.T) {
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

	for i, tc := range []struct{ listen, reason string }{
		{"[fe80::1%eth0]:8443", `must be an https URL, got "https://[fe80::1%eth0]:8443"`},
		{"bücher.internal:8443", `must not contain 'ü'`},
	} {
		cfg := &config.ServerConfig{Server: config.ServerSection{Listen: tc.listen}}
		_, err := createToken(ctx, enrollSrv, db.Clients, cfg, ipc.CreateTokenRequest{Name: fmt.Sprintf("web-%d", i), TTL: time.Hour})
		want := "server.public_url must be set: the URL derived from server.listen " + tc.reason
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("listen %q: error = %v, want %s", tc.listen, err, want)
		}
	}
	tokens, err := db.Tokens.List(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 0 {
		t.Fatalf("stored %d tokens, want none", len(tokens))
	}
}
