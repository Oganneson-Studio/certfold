package ipc

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Oganneson-Studio/sigil/internal/store"
)

type ipcHandlers struct {
	deps ServerDeps
}

type certNameRequest struct {
	Name string `json:"name"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// ---------------------------------------------------------------------------
// /ipc/v1/server/*
// ---------------------------------------------------------------------------

func (h *ipcHandlers) reloadServer(w http.ResponseWriter, r *http.Request) {
	if h.deps.Server.Reload == nil {
		http.Error(w, "server reload unavailable", http.StatusNotImplemented)
		return
	}
	if err := h.deps.Server.Reload(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// /ipc/v1/certs
// ---------------------------------------------------------------------------

func (h *ipcHandlers) listCerts(w http.ResponseWriter, r *http.Request) {
	recs, err := h.deps.DB.Certs.List(r.Context(), nil)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, certificateInfos(recs))
}

func (h *ipcHandlers) upsertCert(w http.ResponseWriter, r *http.Request) {
	var rec store.CertRecord
	if err := readJSON(r, &rec); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	rec.UpdatedAt = time.Now().UTC()
	if err := h.deps.DB.Certs.Upsert(r.Context(), &rec, nil); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ipcHandlers) deleteCert(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := h.deps.DB.Certs.Delete(r.Context(), name, nil); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ipcHandlers) renewCert(w http.ResponseWriter, r *http.Request) {
	if h.deps.Certificates.Renew == nil {
		http.Error(w, "certificate renewal unavailable", http.StatusNotImplemented)
		return
	}
	var req certNameRequest
	if err := readJSON(r, &req); err != nil || req.Name == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := h.deps.Certificates.Renew(r.Context(), req.Name); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// /ipc/v1/clients
// ---------------------------------------------------------------------------

func (h *ipcHandlers) listClients(w http.ResponseWriter, r *http.Request) {
	recs, err := h.deps.DB.Clients.List(r.Context(), nil)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, clientInfos(recs))
}

func (h *ipcHandlers) deleteClient(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := h.deps.DB.Clients.Delete(r.Context(), name, nil); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// /ipc/v1/tokens
// ---------------------------------------------------------------------------

type createTokenRequest struct {
	Name      string        `json:"name"`
	TTL       time.Duration `json:"ttl"`
	ServerURL string        `json:"server_url"`
}

type createTokenResponse struct {
	Token string `json:"token"`
}

func (h *ipcHandlers) createToken(w http.ResponseWriter, r *http.Request) {
	var req createTokenRequest
	if err := readJSON(r, &req); err != nil || req.Name == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.TTL == 0 {
		req.TTL = 24 * time.Hour
	}

	rec := &store.TokenRecord{
		TokenID:   randomHexID(),
		Name:      req.Name,
		ExpiresAt: time.Now().UTC().Add(req.TTL),
		CreatedAt: time.Now().UTC(),
	}
	if err := h.deps.DB.Tokens.Upsert(r.Context(), rec, nil); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, createTokenResponse{Token: rec.TokenID})
}

func (h *ipcHandlers) listTokens(w http.ResponseWriter, r *http.Request) {
	recs, err := h.deps.DB.Tokens.List(r.Context(), nil)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, tokenInfos(recs))
}

func (h *ipcHandlers) deleteToken(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.deps.DB.Tokens.Delete(r.Context(), id, nil); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// /ipc/v1/state
// ---------------------------------------------------------------------------

func (h *ipcHandlers) getState(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	certs, _ := h.deps.DB.Certs.List(ctx, nil)
	clients, _ := h.deps.DB.Clients.List(ctx, nil)
	tokens, _ := h.deps.DB.Tokens.List(ctx, nil)
	writeJSON(w, http.StatusOK, ServerState{
		Certs:   certificateInfos(certs),
		Clients: clientInfos(clients),
		Tokens:  tokenInfos(tokens),
	})
}

// ---------------------------------------------------------------------------
// /ipc/v1/client/*
// ---------------------------------------------------------------------------

type fetchClientRequest struct {
	Name string `json:"name,omitempty"`
}

func (h *ipcHandlers) getClientState(w http.ResponseWriter, r *http.Request) {
	if h.deps.Client.State == nil {
		http.Error(w, "state unavailable", http.StatusNotImplemented)
		return
	}
	state, err := h.deps.Client.State(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if state.Certs == nil {
		state.Certs = map[string]string{}
	}
	writeJSON(w, http.StatusOK, state)
}

func (h *ipcHandlers) fetchClient(w http.ResponseWriter, r *http.Request) {
	if h.deps.Client.Fetch == nil {
		http.Error(w, "fetch unavailable", http.StatusNotImplemented)
		return
	}
	var req fetchClientRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := h.deps.Client.Fetch(r.Context(), req.Name); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ipcHandlers) reloadClient(w http.ResponseWriter, r *http.Request) {
	if h.deps.Client.Reload == nil {
		http.Error(w, "reload unavailable", http.StatusNotImplemented)
		return
	}
	if err := h.deps.Client.Reload(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func randomHexID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
