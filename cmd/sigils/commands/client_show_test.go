package commands

import (
	"context"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

// client show lines its values up one space after the longest label.
func TestClientShowAlignsValues(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := db.Clients.Upsert(ctx, &store.ClientRecord{
		Name:        "web-1",
		Fingerprint: "sha256:AA",
		EnrolledAt:  time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
	}, nil); err != nil {
		t.Fatal(err)
	}
	socket := testIPCSocket(t)
	l, err := ipc.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = ipc.Serve(ctx, l, ipc.ServerDeps{DB: db}) }()
	if _, err := ipc.NewClient(socket); err != nil {
		skipWithoutPipeAccess(t, err)
		t.Fatal(err)
	}

	want := "Name:        web-1\n" +
		"Fingerprint: sha256:AA\n" +
		"Enrolled At: 2026-09-01 12:00:00 UTC\n" +
		"Last Seen:   never\n"
	if got := runSigils(t, "--ipc", socket, "client", "show", "web-1"); got != want {
		t.Fatalf("client show printed:\n%s\nwant:\n%s", got, want)
	}
}
