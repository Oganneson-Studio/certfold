package ipc

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Oganneson-Studio/certfold/internal/config"
	"github.com/Oganneson-Studio/certfold/internal/store"
)

// GET /ipc/v1/certs reports when a stored certificate is due for renewal as
// the daemon's renewal plan says, with its source.
func TestListCertsReportsRenewalPlan(t *testing.T) {
	db := mustOpenDB(t)
	ctx := context.Background()
	spec := config.CertificateSpec{Name: "api-prod", CA: "le", Domains: []string{"api.example.com"}, KeyType: "ec256"}
	cfg := testCertConfig(spec)
	if err := db.Certs.Upsert(ctx, &store.CertRecord{
		Name:            "api-prod",
		CA:              "le",
		Domains:         spec.Domains,
		SpecFingerprint: config.CertificateSpecFingerprint(cfg, spec),
		FullchainPEM:    "fullchain",
		KeyPEM:          "key",
		NotAfter:        time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		Fingerprint:     "sha256:AA",
	}, nil); err != nil {
		t.Fatal(err)
	}
	planned := time.Date(2026, 12, 10, 0, 0, 0, 0, time.UTC)
	deps := certDeps(cfg)
	deps.RenewalPlan = func(record *store.CertRecord) (time.Time, string) {
		if record.Name != "api-prod" || record.Fingerprint != "sha256:AA" {
			t.Errorf("the plan was asked about %+v", record)
		}
		return planned, "ari"
	}
	ts := httptest.NewServer(buildIPCRouter(&ipcHandlers{deps: ServerDeps{DB: db, Certificates: deps}}))
	defer ts.Close()

	certs, err := newTestClient(ts).ListCerts(ctx)
	if err != nil {
		t.Fatalf("ListCerts: %v", err)
	}
	if len(certs) != 1 || !certs[0].RenewAt.Equal(planned) || certs[0].RenewSource != "ari" {
		t.Fatalf("ListCerts = %+v, want api-prod due at %s by ari", certs, planned)
	}
}

func TestListCertsRequiresRenewalPlan(t *testing.T) {
	deps := certDeps(testCertConfig())
	deps.RenewalPlan = nil
	ts := httptest.NewServer(buildIPCRouter(&ipcHandlers{deps: ServerDeps{DB: mustOpenDB(t), Certificates: deps}}))
	defer ts.Close()

	_, err := newTestClient(ts).ListCerts(context.Background())
	if err == nil || !strings.Contains(err.Error(), "501") {
		t.Fatalf("ListCerts error = %v, want 501", err)
	}
}
