package ipc

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Oganneson-Studio/sigil/internal/config"
)

type ipcHandlers struct {
	deps ServerDeps
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
// /ipc/v1/config/certificates
// ---------------------------------------------------------------------------

// addCertificate adds a certificate to server.yaml. It changes only the
// configuration: certificate material still enters the store by issuance
// alone.
func (h *ipcHandlers) addCertificate(w http.ResponseWriter, r *http.Request) {
	if h.deps.Server.AddCertificate == nil {
		http.Error(w, "configuration change unavailable", http.StatusNotImplemented)
		return
	}
	var req AddCertificateRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := h.deps.Server.AddCertificate(r.Context(), config.CertificateSpec{
		Name:        req.Name,
		Domains:     req.Domains,
		CA:          req.CA,
		DNSProvider: req.DNSProvider,
		KeyType:     req.KeyType,
		Subscribers: req.Subscribers,
	}); err != nil {
		// Such as a failed validation, which the operator needs to see.
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	writeJSON(w, http.StatusCreated, ConfigChangeResponse{ConfigPath: h.deps.Server.ConfigPath})
}

// removeCertificate removes a certificate from server.yaml. It answers 404
// with the reason for a name no certificate has, as deleteClient does.
func (h *ipcHandlers) removeCertificate(w http.ResponseWriter, r *http.Request) {
	if h.deps.Server.RemoveCertificate == nil {
		http.Error(w, "configuration change unavailable", http.StatusNotImplemented)
		return
	}
	err := h.deps.Server.RemoveCertificate(r.Context(), chi.URLParam(r, "name"))
	switch {
	case errors.Is(err, config.ErrCertificateNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case err != nil:
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
	default:
		writeJSON(w, http.StatusOK, ConfigChangeResponse{ConfigPath: h.deps.Server.ConfigPath})
	}
}

// ---------------------------------------------------------------------------
// /ipc/v1/certs
// ---------------------------------------------------------------------------

func (h *ipcHandlers) listCerts(w http.ResponseWriter, r *http.Request) {
	if h.deps.Certificates.Current == nil || h.deps.Certificates.Issuing == nil || h.deps.Certificates.RenewalPlan == nil {
		http.Error(w, "certificate status unavailable", http.StatusNotImplemented)
		return
	}
	cfg := h.deps.Certificates.Current()
	recs, err := h.deps.DB.Certs.List(r.Context(), nil)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	statuses, err := h.deps.DB.Issuance.List(r.Context(), nil)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, certificateInfos(cfg, recs, statuses, h.deps.Certificates.Issuing, h.deps.Certificates.RenewalPlan, time.Now()))
}

func (h *ipcHandlers) renewCert(w http.ResponseWriter, r *http.Request) {
	if h.deps.Certificates.Renew == nil {
		http.Error(w, "certificate renewal unavailable", http.StatusNotImplemented)
		return
	}
	var req RenewCertRequest
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

// deleteClient answers 404 with the reason for a name no client has, so the
// CLI does not report a removal that did not happen.
func (h *ipcHandlers) deleteClient(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	err := h.deps.DB.Clients.Delete(r.Context(), name, nil)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		http.Error(w, fmt.Sprintf("client %q is not enrolled", name), http.StatusNotFound)
	case err != nil:
		http.Error(w, "internal error", http.StatusInternalServerError)
	default:
		slog.Info("client removed", "client", name)
		w.WriteHeader(http.StatusNoContent)
	}
}

// ---------------------------------------------------------------------------
// /ipc/v1/tokens
// ---------------------------------------------------------------------------

func (h *ipcHandlers) createToken(w http.ResponseWriter, r *http.Request) {
	var req CreateTokenRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	resp, err := h.deps.Tokens.Create(r.Context(), req)
	if err != nil {
		// The daemon's reason (for example an invalid client name) is what
		// the operator needs to see.
		status := http.StatusUnprocessableEntity
		if errors.Is(err, ErrReplaceRequired) {
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (h *ipcHandlers) listTokens(w http.ResponseWriter, r *http.Request) {
	recs, err := h.deps.DB.Tokens.List(r.Context(), nil)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, tokenInfos(recs))
}

// deleteToken answers 404 with the reason for an ID no token has, as
// deleteClient does. Its event names the token by ID, as every event does.
func (h *ipcHandlers) deleteToken(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	err := h.deps.DB.Tokens.Delete(r.Context(), id, nil)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		http.Error(w, fmt.Sprintf("enrollment token %q does not exist", id), http.StatusNotFound)
	case err != nil:
		http.Error(w, "internal error", http.StatusInternalServerError)
	default:
		slog.Info("enrollment token revoked", "token", id)
		w.WriteHeader(http.StatusNoContent)
	}
}

// ---------------------------------------------------------------------------
// /ipc/v1/client/*
// ---------------------------------------------------------------------------

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
		state.Certs = []ClientCertState{}
	}
	writeJSON(w, http.StatusOK, state)
}

func (h *ipcHandlers) fetchClient(w http.ResponseWriter, r *http.Request) {
	if h.deps.Client.Fetch == nil {
		http.Error(w, "fetch unavailable", http.StatusNotImplemented)
		return
	}
	var req FetchClientRequest
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
