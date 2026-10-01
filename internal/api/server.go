package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Oganneson-Studio/certfold/internal/ca"
	"github.com/Oganneson-Studio/certfold/internal/config"
	"github.com/Oganneson-Studio/certfold/internal/enroll"
	"github.com/Oganneson-Studio/certfold/internal/logging"
	"github.com/Oganneson-Studio/certfold/internal/store"
)

const maxAPIRequestBody = 1 << 20

// Deps bundles all the dependencies an API server needs.
type Deps struct {
	// CurrentServer returns the running configuration, which a reload
	// replaces. Required.
	CurrentServer func() *config.ServerConfig
	DB            *store.DB
	MiniCA        *ca.MiniCA
	EnrollServer  *enroll.Server
	// Changes wakes the GET /v1/sync requests waiting for a change. Required.
	Changes *Changes
	// Done is closed when the daemon shuts down, so that waiting GET /v1/sync
	// requests answer at once instead of holding up the shutdown.
	Done <-chan struct{}
}

// New builds an http.Server configured for mTLS.
//
// getCertificate supplies the server certificate to each handshake, so that
// a new one takes effect without a restart. The certificate should be signed
// by a public CA (or the mini-CA during development). Clients are verified
// against the mini-CA.
func New(deps Deps, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *http.Server {
	r := buildRouter(newHandlers(deps))

	pool := x509.NewCertPool()
	pool.AddCert(deps.MiniCA.Cert())

	tlsCfg := &tls.Config{
		// Clients that present a certificate must have it signed by mini-CA.
		// Routes that don't need mTLS are protected by middleware instead.
		ClientAuth:     tls.VerifyClientCertIfGiven,
		ClientCAs:      pool,
		GetCertificate: getCertificate,
		// For the install scripts: Windows PowerShell 5.1 offers at most TLS
		// 1.2 on older Windows. certfoldc itself requires TLS 1.3.
		MinVersion: tls.VersionTLS12,
	}

	return &http.Server{
		Addr:              deps.CurrentServer().Server.Listen,
		Handler:           r,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func buildRouter(h *handlers) http.Handler {
	r := chi.NewRouter()
	r.Use(logging.Recoverer)

	// Public — no auth.
	r.Get("/install.sh", h.installSh)
	r.Get("/install.ps1", h.installPs1)
	r.Get("/download/certfoldc", h.downloadCertfoldc)

	// Enroll — token auth, must NOT have mTLS client cert.
	r.With(limitRequestBody(maxAPIRequestBody)).Post("/v1/enroll", h.enroll)

	// Authenticated via mTLS.
	r.Group(func(r chi.Router) {
		r.Use(requireMTLS)
		r.Use(h.requireActiveClient)
		r.Get("/v1/sync", h.syncCertificates)
		r.Get("/v1/certificates/{name}/bundle", h.getCertBundle)
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
