package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/Oganneson-Studio/sigil/internal/logging"
	"github.com/Oganneson-Studio/sigil/pkg/proto"
)

// setupLogs runs logging.Setup with a service log that is discarded, for the
// duration of t. Setup also routes the standard log package through slog,
// which restoring the default logger does not undo, so the cleanup restores
// that as well.
func setupLogs(t *testing.T) logging.Logs {
	t.Helper()
	logger, writer, flags := slog.Default(), log.Writer(), log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(logger)
		log.SetOutput(writer)
		log.SetFlags(flags)
	})
	return logging.Setup(slog.NewTextHandler(io.Discard, nil))
}

// eventLines returns the events of logs as "LEVEL message attrs".
func eventLines(logs logging.Logs) []string {
	var lines []string
	for _, e := range logs.Events.Since(0) {
		lines = append(lines, strings.TrimSpace(e.Level+" "+e.Message+" "+e.Attrs))
	}
	return lines
}

func TestRouterLogsPanicsAsEvents(t *testing.T) {
	logs := setupLogs(t)
	router := buildRouter(newHandlers(buildDeps(t))).(*chi.Mux)
	router.Get("/panic", func(http.ResponseWriter, *http.Request) { panic("boom") })

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/panic", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	want := "ERROR panic serving request method=GET path=/panic panic=boom stack=(withheld)"
	if got := eventLines(logs); len(got) != 1 || got[0] != want {
		t.Fatalf("events = %q, want %q", got, want)
	}
}

func TestIdentityRenewalEvents(t *testing.T) {
	logs := setupLogs(t)
	deps := buildDeps(t)
	handler := newHandler(deps)
	oldIdentity := makeEnrolledClientCert(t, deps, "web-1")

	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, newKey)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(proto.RenewIdentityRequest{
		CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, simulateMTLS(httptest.NewRequest(http.MethodPost, "/v1/identity/renew", bytes.NewReader(body)), oldIdentity))
	if rec.Code != http.StatusOK {
		t.Fatalf("renew status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var response proto.RenewIdentityResponse
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(newKey)
	if err != nil {
		t.Fatal(err)
	}
	newIdentity, err := tls.X509KeyPair([]byte(response.ClientCert), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}

	// The first request with the new identity switches to it; the second
	// finds it in place.
	for range 2 {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, syncRequest(&newIdentity, ""))
		if rec.Code != http.StatusOK {
			t.Fatalf("sync status = %d, body = %s", rec.Code, rec.Body.String())
		}
	}

	got := eventLines(logs)
	if len(got) != 2 || !strings.HasPrefix(got[0], "INFO client identity renewal issued client=web-1 not_after=") ||
		got[1] != "INFO client identity switched client=web-1" {
		t.Fatalf("events = %q, want the renewal issued, then one switch", got)
	}
}

func TestLastSeenWriteFailureIsAnErrorEvent(t *testing.T) {
	logs := setupLogs(t)
	deps, other := buildFileDeps(t)
	identity := makeEnrolledClientCert(t, deps, "web-1")
	ctx := context.Background()
	// As in TestAuthenticatedRequestIsServedWhenLastSeenCannotBeWritten, the
	// other handle fails its write at once while this one holds the lock.
	locker := deps.DB
	deps.DB = other
	record, err := locker.Clients.Get(ctx, "web-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := locker.BeginTx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := locker.Clients.Upsert(ctx, record, tx); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	newHandler(deps).ServeHTTP(rec, syncRequest(identity, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := eventLines(logs); len(got) != 1 || !strings.HasPrefix(got[0], "ERROR record last_seen failed client=web-1 error=") {
		t.Fatalf("events = %q, want one ERROR record last_seen failed", got)
	}
}
