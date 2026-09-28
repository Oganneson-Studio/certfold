package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/Oganneson-Studio/sigil/internal/ca"
	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/enroll"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

const maxAPIRequestBody = 1 << 20

// Deps bundles all the dependencies an API server needs.
type Deps struct {
	ServerCfg     *config.ServerConfig
	CurrentServer func() *config.ServerConfig
	DB            *store.DB
	MiniCA        *ca.MiniCA
	DataDir       string
	EnrollServer  *enroll.Server
	// Changes wakes the GET /v1/sync requests waiting for a change. Required.
	Changes *Changes
	// Done is closed when the daemon shuts down, so that waiting GET /v1/sync
	// requests answer at once instead of holding up the shutdown.
	Done <-chan struct{}
}

func (d Deps) serverConfig() *config.ServerConfig {
	if d.CurrentServer != nil {
		return d.CurrentServer()
	}
	return d.ServerCfg
}

// New builds an http.Server configured for mTLS.
//
// TLS certificate used for the listener must be provided via tlsCert.
// It should be a certificate signed by a public CA (or the mini-CA during
// development). Clients are verified against the mini-CA.
func New(deps Deps, tlsCert tls.Certificate) *http.Server {
	h := newHandlers(deps)
	r := buildRouter(h)
	cfg := deps.serverConfig()

	pool := x509.NewCertPool()
	pool.AddCert(deps.MiniCA.Cert())

	tlsCfg := &tls.Config{
		// Clients that present a certificate must have it signed by mini-CA.
		// Routes that don't need mTLS are protected by middleware instead.
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pool,
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
	}

	return &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           r,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}

// NewInsecure builds a plain HTTP server (for tests only).
func NewInsecure(deps Deps) *http.Server {
	h := newHandlers(deps)
	cfg := deps.serverConfig()
	return &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           buildRouter(h),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}

func buildRouter(h *handlers) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)

	// Public — no auth.
	r.Get("/install.sh", h.installSh)
	r.Get("/install.ps1", h.installPs1)
	r.Get("/download/sigilc", h.downloadSigilc)

	// Enroll — token auth, must NOT have mTLS client cert.
	r.With(limitRequestBody(maxAPIRequestBody)).Post("/v1/enroll", h.enroll)

	// Authenticated via mTLS.
	r.Group(func(r chi.Router) {
		r.Use(requireMTLS)
		r.Use(h.requireActiveClient)
		r.Get("/v1/certificates", h.listCertificates)
		r.Get("/v1/certificates/{name}/bundle", h.getCertBundle)
		r.With(limitRequestBody(maxAPIRequestBody)).Post("/v1/heartbeat", h.heartbeat)
		r.With(limitRequestBody(maxAPIRequestBody)).Post("/v1/identity/renew", h.renewIdentity)
	})

	return r
}

func limitRequestBody(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}

// requireMTLS is a middleware that rejects requests without a verified peer certificate.
func requireMTLS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "mTLS client certificate required", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), clientCertKey{}, r.TLS.PeerCertificates[0])
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type clientCertKey struct{}

// peerCert extracts the verified peer certificate from the request context.
func peerCert(r *http.Request) *x509.Certificate {
	c, _ := r.Context().Value(clientCertKey{}).(*x509.Certificate)
	return c
}
