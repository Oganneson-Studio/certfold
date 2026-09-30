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
	// Times show in local time, with the offset from UTC.
	enrolled := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	seen := enrolled.Add(26 * time.Hour)
	for _, rec := range []*store.ClientRecord{
		{Name: "web-1", Fingerprint: "sha256:AA", EnrolledAt: enrolled},
		{Name: "web-2", Fingerprint: "sha256:BB", EnrolledAt: enrolled, LastSeen: seen},
	} {
		if err := db.Clients.Upsert(ctx, rec, nil); err != nil {
			t.Fatal(err)
		}
	}
	socket := testIPCSocket(t)
	l, err := ipc.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := ipc.NewServer(ipc.ServerDeps{DB: db})
	context.AfterFunc(ctx, func() { _ = srv.Close() })
	go func() { _ = srv.Serve(l) }()
	if _, err := ipc.NewClient(socket); err != nil {
		skipWithoutPipeAccess(t, err)
		t.Fatal(err)
	}

	const layout = "2006-01-02 15:04:05 -07:00"
	for name, want := range map[string]string{
		"web-1": "Name:        web-1\n" +
			"Fingerprint: sha256:AA\n" +
			"Enrolled At: " + enrolled.Local().Format(layout) + "\n" +
			"Last Seen:   never\n",
		"web-2": "Name:        web-2\n" +
			"Fingerprint: sha256:BB\n" +
			"Enrolled At: " + enrolled.Local().Format(layout) + "\n" +
			"Last Seen:   " + seen.Local().Format(layout) + "\n",
	} {
		if got := runSigils(t, "--ipc", socket, "client", "show", name); got != want {
			t.Errorf("client show %s printed:\n%s\nwant:\n%s", name, got, want)
		}
	}
}
