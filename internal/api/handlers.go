package api

import (
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Oganneson-Studio/sigil/internal/ca"
	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/store"
	"github.com/Oganneson-Studio/sigil/pkg/proto"
)

// lastSeenInterval is the least time between two writes of one client's
// last_seen. A variable so that tests can shorten it.
var lastSeenInterval = time.Minute

type handlers struct {
	deps Deps

	// seenMu guards lastSeen, which holds for each client the time its
	// last_seen was last written, or is being written.
	seenMu   sync.Mutex
	lastSeen map[string]time.Time
}

func newHandlers(deps Deps) *handlers {
	return &handlers{deps: deps, lastSeen: make(map[string]time.Time)}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// ---------------------------------------------------------------------------
// GET /install.sh
// ---------------------------------------------------------------------------

func (h *handlers) installSh(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript")
	renderInstallSh(w, h.deps.serverConfig().PublicBaseURL())
}

// ---------------------------------------------------------------------------
// GET /install.ps1
// ---------------------------------------------------------------------------

func (h *handlers) installPs1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	token := r.URL.Query().Get("token")
	if token != "" && !validEnrollmentToken(token) {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}
	renderInstallPs1(w, h.deps.serverConfig().PublicBaseURL(), token)
}

// ---------------------------------------------------------------------------
// GET /download/sigilc?os=linux&arch=amd64
// ---------------------------------------------------------------------------

func (h *handlers) downloadSigilc(w http.ResponseWriter, r *http.Request) {
	goos := r.URL.Query().Get("os")
	goarch := r.URL.Query().Get("arch")
	if goos == "" {
		goos = runtime.GOOS
	}
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	if !validPlatformPart(goos) || !validPlatformPart(goarch) {
		http.Error(w, "invalid platform", http.StatusBadRequest)
		return
	}

	name := fmt.Sprintf("sigilc-%s-%s", goos, goarch)
	if goos == "windows" {
		name += ".exe"
	}
	baseDir := filepath.Join(h.deps.DataDir, "binaries")
	path := filepath.Join(baseDir, name)
	rel, err := filepath.Rel(baseDir, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		http.Error(w, "invalid platform", http.StatusBadRequest)
		return
	}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "binary not found for requested platform", http.StatusNotFound)
		} else {
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}
	defer f.Close()

	// Serve sha256 if requested.
	if r.URL.Query().Get("sha256") == "1" {
		data, err := io.ReadAll(f)
		if err != nil {
			http.Error(w, "read error", http.StatusInternalServerError)
			return
		}
		sum := sha256.Sum256(data)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "%x", sum[:])
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = io.Copy(w, f)
}

func validPlatformPart(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func validEnrollmentToken(s string) bool {
	if s == "" || len(s) > 64*1024 {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') &&
			(r < 'A' || r > 'Z') &&
			(r < '0' || r > '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// POST /v1/enroll
// ---------------------------------------------------------------------------

func (h *handlers) enroll(w http.ResponseWriter, r *http.Request) {
	// Reject if the request arrived with a client certificate (misuse guard).
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		http.Error(w, "enroll must not use a client certificate", http.StatusBadRequest)
		return
	}

	var req proto.EnrollRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Token == "" || req.CSR == "" {
		http.Error(w, "token and csr are required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Verify token via enroll.Server (decodes base64, checks secret hash, expiry, replay).
	name, tokenID, err := h.deps.EnrollServer.Verify(ctx, req.Token)
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	// Parse CSR.
	block, _ := pem.Decode([]byte(req.CSR))
	if block == nil {
		http.Error(w, "invalid CSR PEM", http.StatusBadRequest)
		return
	}
	csrDER := block.Bytes

	// Sign the client cert, mark token used, record client — all via enroll.Server.
	certDER, err := h.deps.EnrollServer.SignClientCert(ctx, csrDER, name, tokenID)
	if err != nil {
		http.Error(w, "sign error", http.StatusInternalServerError)
		return
	}
	slog.Info("client enrolled", "client", name, "token", tokenID)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	writeJSON(w, http.StatusOK, proto.EnrollResponse{
		CACert:     string(h.deps.MiniCA.CertPEM()),
		ClientCert: string(certPEM),
	})
}

// ---------------------------------------------------------------------------
// GET /v1/certificates/{name}/bundle
// ---------------------------------------------------------------------------

func (h *handlers) getCertBundle(w http.ResponseWriter, r *http.Request) {
	cert := peerCert(r)
	if cert == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	clientName := cert.Subject.CommonName
	certName := chi.URLParam(r, "name")

	cfg := h.deps.serverConfig()
	spec, subscribed := subscribedSpecs(cfg, clientName)[certName]
	if !subscribed {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	ctx := r.Context()
	rec, err := h.deps.DB.Certs.Get(ctx, certName, nil)
	if err == sql.ErrNoRows {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !certRecordMatchesSpec(rec, cfg, spec) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	writeJSON(w, http.StatusOK, proto.CertBundle{
		Name:         rec.Name,
		Fingerprint:  rec.Fingerprint,
		FullchainPEM: rec.FullchainPEM,
		KeyPEM:       rec.KeyPEM,
	})
}

// ---------------------------------------------------------------------------
// POST /v1/identity/renew
// ---------------------------------------------------------------------------

func (h *handlers) renewIdentity(w http.ResponseWriter, r *http.Request) {
	cert := peerCert(r)
	if cert == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req proto.RenewIdentityRequest
	if err := readJSON(r, &req); err != nil || req.CSR == "" {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	block, rest := pem.Decode([]byte(req.CSR))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(strings.TrimSpace(string(rest))) != 0 {
		http.Error(w, "invalid CSR PEM", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		http.Error(w, "invalid CSR", http.StatusBadRequest)
		return
	}

	clientName := cert.Subject.CommonName
	certDER, err := h.deps.MiniCA.Sign(csr, clientName)
	if err != nil {
		http.Error(w, "sign error", http.StatusInternalServerError)
		return
	}
	issued, err := x509.ParseCertificate(certDER)
	if err != nil {
		http.Error(w, "sign error", http.StatusInternalServerError)
		return
	}
	if err := h.deps.DB.Clients.StagePendingIdentity(
		r.Context(), clientName, ca.Fingerprint(certDER), issued.NotAfter,
	); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	slog.Info("client identity renewal issued", "client", clientName, "not_after", issued.NotAfter)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	writeJSON(w, http.StatusOK, proto.RenewIdentityResponse{ClientCert: string(certPEM)})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// subscribedSpecs returns the specs clientName subscribes to. Subscribers are
// validated client names (config.ValidateClientName), so the match is exact.
func subscribedSpecs(cfg *config.ServerConfig, clientName string) map[string]config.CertificateSpec {
	out := make(map[string]config.CertificateSpec)
	for _, spec := range cfg.Certificates {
		if slices.Contains(spec.Subscribers, clientName) {
			out[spec.Name] = spec
		}
	}
	return out
}

func certRecordMatchesSpec(rec *store.CertRecord, cfg *config.ServerConfig, spec config.CertificateSpec) bool {
	return rec != nil &&
		rec.CA == spec.CA &&
		slices.Equal(rec.Domains, spec.Domains) &&
		rec.SpecFingerprint == config.CertificateSpecFingerprint(cfg, spec)
}

func (h *handlers) requireActiveClient(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cert := peerCert(r)
		if cert == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		clientName := cert.Subject.CommonName
		fingerprint := ca.Fingerprint(cert.Raw)
		now := time.Now()
		rec, err := h.deps.DB.Clients.Get(r.Context(), clientName, nil)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if rec.Fingerprint != fingerprint {
			if rec.PendingFingerprint != fingerprint || !now.Before(rec.PendingNotAfter) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if err := h.deps.DB.Clients.PromotePendingIdentity(
				r.Context(), clientName, fingerprint, now,
			); err != nil {
				// A concurrent first use of the same identity may have
				// promoted it since the lookup above.
				current, err := h.deps.DB.Clients.Get(r.Context(), clientName, nil)
				if err != nil || current.Fingerprint != fingerprint {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
			} else {
				slog.Info("client identity switched", "client", clientName)
			}
		}

		// Record last_seen at most once per lastSeenInterval for each client.
		// The throttle is kept here, not in the UPDATE, so that an UPDATE of
		// zero rows still means the client is gone. Claiming the entry before
		// the write leaves one writer among concurrent requests. The claim
		// stands whatever the write returns, so a database that fails it is
		// tried again once per interval.
		h.seenMu.Lock()
		last, seen := h.lastSeen[clientName]
		write := !seen || now.Sub(last) >= lastSeenInterval
		if write {
			h.lastSeen[clientName] = now
		}
		h.seenMu.Unlock()
		if write {
			// A single conditional write: the client may have been removed, or
			// its identity changed, since the lookup above.
			err := h.deps.DB.Clients.MarkSeen(r.Context(), clientName, fingerprint, now)
			if err == sql.ErrNoRows {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if err != nil {
				// The lookup above authenticated the client; last_seen only
				// records that it was here. A database that cannot take writes
				// must not keep it from the certificates already stored.
				slog.Error("record last_seen failed", "client", clientName, "error", err)
			}
		}
		next.ServeHTTP(w, r)
	})
}
