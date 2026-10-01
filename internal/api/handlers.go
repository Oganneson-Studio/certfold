package api

import (
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
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
	"github.com/Oganneson-Studio/sigil/internal/enroll"
	"github.com/Oganneson-Studio/sigil/internal/store"
	"github.com/Oganneson-Studio/sigil/pkg/proto"
)

// lastSeenInterval is the least time between two writes of one client's
// last_seen by the same identity. A variable so that tests can shorten it.
var lastSeenInterval = time.Minute

// downloadWriteTimeout is how long GET /download/sigilc may take to send the
// binary. Anyone can download it, so a reader that slow holds a connection
// that long.
const downloadWriteTimeout = 10 * time.Minute

// renewInterval is the least time between two identity renewals of one
// client. sigilc renews its identity about every 60 days.
const renewInterval = time.Minute

type handlers struct {
	deps Deps

	// seenMu guards lastSeen, which holds for each client the claim on its
	// last_seen write. Another identity of the client replaces the claim, so
	// there is one entry per client name.
	seenMu   sync.Mutex
	lastSeen map[string]seenClaim

	// syncMu guards syncing, which counts for each client its GET /v1/sync
	// requests in progress.
	syncMu  sync.Mutex
	syncing map[string]int

	// renewMu guards renewed, which holds for each client the time of its
	// last identity renewal, or of the one in progress.
	renewMu sync.Mutex
	renewed map[string]time.Time
}

func newHandlers(deps Deps) *handlers {
	return &handlers{
		deps:     deps,
		lastSeen: make(map[string]seenClaim),
		syncing:  make(map[string]int),
		renewed:  make(map[string]time.Time),
	}
}

// seenClaim is the identity, by certificate fingerprint, that last wrote a
// client's last_seen, or is writing it, and when.
type seenClaim struct {
	fingerprint string
	at          time.Time
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

// parseCSR reads the CSR of an enrollment or identity renewal: one PEM
// CERTIFICATE REQUEST block and nothing else, signed by its own key. The
// error is the answer to the client.
func parseCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, rest := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, errors.New("invalid CSR")
	}
	return csr, nil
}

// serverError answers 500 and logs msg with the slog attributes args: the
// client learns only that the server failed, so the log is the one place
// that says why.
func serverError(w http.ResponseWriter, msg string, args ...any) {
	slog.Error(msg, args...)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// ---------------------------------------------------------------------------
// GET /install.sh
// ---------------------------------------------------------------------------

func (h *handlers) installSh(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript")
	renderInstallSh(w, h.deps.CurrentServer().PublicBaseURL())
}

// ---------------------------------------------------------------------------
// GET /install.ps1
// ---------------------------------------------------------------------------

// installPs1 serves the same script to every request and reads nothing from
// it: the token is the -Token argument of the command that runs the script.
func (h *handlers) installPs1(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	renderInstallPs1(w, h.deps.CurrentServer().PublicBaseURL())
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
	baseDir := filepath.Join(h.deps.CurrentServer().Server.DataDir, "binaries")
	path := filepath.Join(baseDir, name)
	rel, err := filepath.Rel(baseDir, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		http.Error(w, "invalid platform", http.StatusBadRequest)
		return
	}

	f, err := os.Open(path)
	if os.IsNotExist(err) {
		http.Error(w, "binary not found for requested platform", http.StatusNotFound)
		return
	}
	if err != nil {
		serverError(w, "open sigilc binary failed", "error", err)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		serverError(w, "open sigilc binary failed", "error", err)
		return
	}

	// sigilc is about 20 MB, which a link below about 5 Mbit/s does not carry
	// within the server's WriteTimeout. Only this response's deadline moves,
	// as in GET /v1/sync; httptest.ResponseRecorder does not support
	// deadlines.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(downloadWriteTimeout))
	// Set before ServeContent, which would otherwise sniff the type.
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, name, info.ModTime(), f)
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
	csr, err := parseCSR(req.CSR)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Verify token via enroll.Server (decodes base64, checks secret hash, expiry, replay).
	name, tokenID, err := h.deps.EnrollServer.Verify(ctx, req.Token)
	// A token that can no longer enroll says why, to its holder and to the
	// log; enroll.Server says it only once the secret checks out.
	refuse := func(err error) {
		slog.Warn("enrollment refused", "client", name, "token", tokenID, "error", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
	}
	switch {
	case errors.Is(err, enroll.ErrInvalidToken):
		// Anyone can send one, so it goes unlogged.
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	case errors.Is(err, enroll.ErrTokenUsed), errors.Is(err, enroll.ErrTokenExpired):
		refuse(err)
		return
	case err != nil:
		serverError(w, "enrollment failed", "error", err)
		return
	}

	// Sign the client cert, mark token used, record client — all via enroll.Server.
	certDER, err := h.deps.EnrollServer.SignClientCert(ctx, csr, name, tokenID)
	if errors.Is(err, enroll.ErrTokenUsed) {
		refuse(err)
		return
	}
	if err != nil {
		serverError(w, "enrollment failed", "client", name, "token", tokenID, "error", err)
		return
	}
	slog.Info("client enrolled", "client", name, "token", tokenID)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	writeJSON(w, http.StatusOK, proto.EnrollResponse{ClientCert: string(certPEM)})
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

	cfg := h.deps.CurrentServer()
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
		serverError(w, "read certificate failed", "client", clientName, "cert", certName, "error", err)
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
	clientName := cert.Subject.CommonName

	// Each renewal syncs the serial file to disk and logs an event, so a
	// client that renewed in a loop would flush the event ring within
	// seconds. As with last_seen, the claim stands whatever the renewal
	// returns, and sigilc backs off on the 429.
	now := time.Now()
	h.renewMu.Lock()
	last, seen := h.renewed[clientName]
	allowed := !seen || now.Sub(last) >= renewInterval
	if allowed {
		h.renewed[clientName] = now
	}
	h.renewMu.Unlock()
	if !allowed {
		http.Error(w, "identity renewed less than a minute ago", http.StatusTooManyRequests)
		return
	}

	var req proto.RenewIdentityRequest
	if err := readJSON(r, &req); err != nil || req.CSR == "" {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	csr, err := parseCSR(req.CSR)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	certDER, err := h.deps.MiniCA.Sign(csr, clientName)
	if err != nil {
		serverError(w, "client identity renewal failed", "client", clientName, "error", err)
		return
	}
	issued, err := x509.ParseCertificate(certDER)
	if err != nil {
		serverError(w, "client identity renewal failed", "client", clientName, "error", err)
		return
	}
	err = h.deps.DB.Clients.StagePendingIdentity(
		r.Context(), clientName, ca.Fingerprint(cert.Raw), ca.Fingerprint(certDER), issued.NotAfter,
	)
	if err == sql.ErrNoRows {
		// The identity that asked was replaced, or its client removed,
		// since the check of this request.
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err != nil {
		serverError(w, "client identity renewal failed", "client", clientName, "error", err)
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

// certRecordMatchesSpec reports whether rec was issued for spec as cfg has
// it. The fingerprint covers the CA and its directory, the domains and the
// key type.
func certRecordMatchesSpec(rec *store.CertRecord, cfg *config.ServerConfig, spec config.CertificateSpec) bool {
	return rec != nil && rec.SpecFingerprint == config.CertificateSpecFingerprint(cfg, spec)
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
		if err == sql.ErrNoRows {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if err != nil {
			serverError(w, "look up client failed", "client", clientName, "error", err)
			return
		}
		if rec.Fingerprint != fingerprint {
			if rec.PendingFingerprint != fingerprint || !now.Before(rec.PendingNotAfter) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			err := h.deps.DB.Clients.PromotePendingIdentity(r.Context(), clientName, fingerprint, now)
			switch {
			case err == nil:
				slog.Info("client identity switched", "client", clientName)
			case err == sql.ErrNoRows:
				// A concurrent first use of the same identity may have
				// promoted it since the lookup above.
				current, err := h.deps.DB.Clients.Get(r.Context(), clientName, nil)
				if err != nil && err != sql.ErrNoRows {
					serverError(w, "look up client failed", "client", clientName, "error", err)
					return
				}
				if err != nil || current.Fingerprint != fingerprint {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
			default:
				serverError(w, "promote client identity failed", "client", clientName, "error", err)
				return
			}
		}

		// Record last_seen at most once per lastSeenInterval for each client,
		// and at once for an identity other than the one that claimed the
		// last write. The throttle is kept here, not in the UPDATE, so that
		// an UPDATE of zero rows still means the client is gone. Claiming the
		// entry before the write leaves one writer among concurrent requests.
		// The claim stands whatever the write returns, so a database that
		// fails it is tried again once per interval. A client enrolled again
		// has a new identity and no last_seen, which a claim of its old
		// identity would leave empty for up to an interval. Requests of a
		// pending identity and the active one that alternate, for the short
		// while around a promotion, write each time the identity changes.
		h.seenMu.Lock()
		claim, claimed := h.lastSeen[clientName]
		write := !claimed || claim.fingerprint != fingerprint || now.Sub(claim.at) >= lastSeenInterval
		if write {
			h.lastSeen[clientName] = seenClaim{fingerprint: fingerprint, at: now}
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
