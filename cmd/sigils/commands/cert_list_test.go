package commands

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

// cert list lines its columns up however long a certificate's name is.
func TestCertListAlignsLongNames(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// The store keeps whole seconds.
	now := time.Now().UTC().Truncate(time.Second)
	notAfter := now.Add(60 * 24 * time.Hour)
	api := config.CertificateSpec{Name: "api", CA: "le", Domains: []string{"api.example.com"}, KeyType: "ec256"}
	long := config.CertificateSpec{Name: "a-certificate-name-far-longer-than-twenty-characters", CA: "le",
		Domains: []string{"long.example.com"}, KeyType: "ec256"}
	cfg := &config.ServerConfig{
		ACME: config.ACMESection{CAs: map[string]config.CAEntry{
			"le": {Directory: "https://acme.example.com/directory"},
		}},
		Certificates: []config.CertificateSpec{api, long},
	}
	if err := db.Certs.Upsert(context.Background(), &store.CertRecord{
		Name:            long.Name,
		CA:              "le",
		Domains:         long.Domains,
		SpecFingerprint: config.CertificateSpecFingerprint(cfg, long),
		NotAfter:        notAfter,
		Fingerprint:     "sha256:AA",
		IssuedAt:        now,
		UpdatedAt:       now,
	}, nil); err != nil {
		t.Fatal(err)
	}
	socket := serveCertificates(t, db, cfg)

	table := runSigils(t, "--ipc", socket, "cert", "list")
	rows := [][]string{
		{"NAME", "CA", "DOMAINS", "STATE", "NOT AFTER", "RENEW AT"},
		{"api", "le", "api.example.com", "pending", "-", "-"},
		{long.Name, "le", "long.example.com", "valid", notAfter.Format("2006-01-02"),
			notAfter.Add(-20*24*time.Hour).Format("2006-01-02") + " (ari)"},
	}
	lines := strings.Split(strings.TrimSuffix(table, "\n"), "\n")
	if len(lines) != len(rows) {
		t.Fatalf("cert list printed %d lines, want %d:\n%s", len(lines), len(rows), table)
	}
	// Every cell starts where the heading of its column does.
	for col, heading := range rows[0] {
		at := strings.Index(lines[0], heading)
		for i, row := range rows {
			if !strings.HasPrefix(lines[i][min(at, len(lines[i])):], row[col]) {
				t.Fatalf("%s of line %d does not start at column %d:\n%s", heading, i, at, table)
			}
		}
	}
}
