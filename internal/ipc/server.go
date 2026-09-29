package ipc

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/logging"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

// maxRequestBody bounds every IPC request body. The legitimate ones are small
// JSON objects, such as the name of a certificate or client, far below it.
const maxRequestBody = 1 << 20

// ServerDeps holds the dependencies for the IPC server.
type ServerDeps struct {
	DB           *store.DB
	Server       *ServerControlDeps
	Certificates *CertificateControlDeps
	Tokens       *TokenControlDeps
	Client       *ClientControlDeps
	// Events holds the recent events of the daemon, sigils or sigilc.
	Events *logging.Ring
}

// ServerControlDeps exposes runtime operations implemented by sigils.
type ServerControlDeps struct {
	Reload func(context.Context) error
}

// CertificateControlDeps exposes runtime certificate operations implemented
// by the sigils daemon.
type CertificateControlDeps struct {
	Renew func(context.Context, string) error
	// Current returns the running configuration.
	Current func() *config.ServerConfig
	// Issuing reports whether an issuance of the named certificate is running or waiting for a slot.
	Issuing func(name string) bool
	// RenewalPlan returns when a stored certificate that matches the running
	// configuration is due for renewal, and the source of that time: "ari" or
	// "ratio". The zero time means at once.
	RenewalPlan func(*store.CertRecord) (time.Time, string)
}

// TokenControlDeps exposes enrollment-token operations implemented by the
// sigils daemon.
type TokenControlDeps struct {
	Create func(ctx context.Context, req CreateTokenRequest) (CreateTokenResponse, error)
}

// ClientControlDeps exposes the operations supported by a sigilc daemon.
// It is optional because the same IPC package is also used by sigils.
type ClientControlDeps struct {
	State  func(context.Context) (ClientState, error)
	Fetch  func(context.Context, string) error
	Reload func(context.Context) error
}

// NewServer constructs an *http.Server that serves over the provided listener.
// It does NOT call ListenAndServe — the caller owns starting and stopping.
func NewServer(deps ServerDeps) *http.Server {
	h := &ipcHandlers{deps: deps}
	return &http.Server{Handler: buildIPCRouter(h)}
}

func buildIPCRouter(h *ipcHandlers) http.Handler {
	r := chi.NewRouter()
	r.Use(logging.Recoverer)
	r.Use(middleware.RequestSize(maxRequestBody))

	if h.deps.DB != nil {
		r.Get("/ipc/v1/clients", h.listClients)
		r.Delete("/ipc/v1/clients/{name}", h.deleteClient)

		r.Get("/ipc/v1/tokens", h.listTokens)
		r.Delete("/ipc/v1/tokens/{id}", h.deleteToken)
	}
	if h.deps.Server != nil {
		r.Post("/ipc/v1/server/reload", h.reloadServer)
	}
	if h.deps.Certificates != nil {
		r.Get("/ipc/v1/certs", h.listCerts)
		r.Post("/ipc/v1/certs/renew", h.renewCert)
	}
	if h.deps.Tokens != nil {
		r.Post("/ipc/v1/tokens", h.createToken)
	}

	if h.deps.Client != nil {
		r.Get("/ipc/v1/client/state", h.getClientState)
		r.Post("/ipc/v1/client/fetch", h.fetchClient)
		r.Post("/ipc/v1/client/reload", h.reloadClient)
	}

	if h.deps.Events != nil {
		r.Get("/ipc/v1/events", h.listEvents)
	}

	return r
}
