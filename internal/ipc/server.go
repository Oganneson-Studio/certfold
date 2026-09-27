package ipc

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/Oganneson-Studio/sigil/internal/store"
)

// ServerDeps holds the dependencies for the IPC server.
type ServerDeps struct {
	DB           *store.DB
	Server       *ServerControlDeps
	Certificates *CertificateControlDeps
	Client       *ClientControlDeps
}

// ServerControlDeps exposes runtime operations implemented by sigils.
type ServerControlDeps struct {
	Reload func(context.Context) error
}

// CertificateControlDeps exposes runtime certificate operations implemented
// by the sigils daemon.
type CertificateControlDeps struct {
	Renew func(context.Context, string) error
}

// ClientControlDeps exposes the operations supported by a sigilc daemon.
// It is optional because the same IPC package is also used by sigils.
type ClientControlDeps struct {
	State  func(context.Context) (ClientState, error)
	Fetch  func(context.Context, string) error
	Reload func(context.Context) error
}

// ClientState is the runtime status returned by a sigilc daemon.
type ClientState struct {
	Name       string            `json:"name"`
	ServerURL  string            `json:"server_url"`
	Online     bool              `json:"online"`
	LastPullAt time.Time         `json:"last_pull_at,omitempty"`
	LastError  string            `json:"last_error,omitempty"`
	Certs      map[string]string `json:"certs"`
}

// NewServer constructs an *http.Server that serves over the provided listener.
// It does NOT call ListenAndServe — the caller owns starting and stopping.
func NewServer(deps ServerDeps) *http.Server {
	h := &ipcHandlers{deps: deps}
	return &http.Server{Handler: buildIPCRouter(h)}
}

// Serve accepts connections from l and serves IPC requests until ctx is done.
func Serve(ctx context.Context, l net.Listener, deps ServerDeps) error {
	srv := NewServer(deps)
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	err := srv.Serve(l)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func buildIPCRouter(h *ipcHandlers) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)

	if h.deps.DB != nil {
		r.Get("/ipc/v1/certs", h.listCerts)
		r.Post("/ipc/v1/certs", h.upsertCert)
		r.Delete("/ipc/v1/certs/{name}", h.deleteCert)

		r.Get("/ipc/v1/clients", h.listClients)
		r.Delete("/ipc/v1/clients/{name}", h.deleteClient)

		r.Post("/ipc/v1/tokens", h.createToken)
		r.Get("/ipc/v1/tokens", h.listTokens)
		r.Delete("/ipc/v1/tokens/{id}", h.deleteToken)

		r.Get("/ipc/v1/state", h.getState)
	}
	if h.deps.Server != nil {
		r.Post("/ipc/v1/server/reload", h.reloadServer)
	}
	if h.deps.Certificates != nil {
		r.Post("/ipc/v1/certs/renew", h.renewCert)
	}

	if h.deps.Client != nil {
		r.Get("/ipc/v1/client/state", h.getClientState)
		r.Post("/ipc/v1/client/fetch", h.fetchClient)
		r.Post("/ipc/v1/client/reload", h.reloadClient)
	}

	return r
}
