package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/ca"
	"github.com/Oganneson-Studio/sigil/pkg/proto"
)

// syncMaxWait is how long GET /v1/sync holds a request whose view has not
// changed. A variable so that tests can shorten it.
var syncMaxWait = proto.SyncMaxWait

// ---------------------------------------------------------------------------
// GET /v1/sync
// ---------------------------------------------------------------------------

// syncCertificates answers with the client's view and its ETag. A request
// whose If-None-Match equals that ETag waits up to syncMaxWait for the view to
// change, and answers 304 if it does not. If-None-Match is compared as a
// whole, so a weak or wildcard value or a list, in one field line or several,
// never matches and the request answers at once.
func (h *handlers) syncCertificates(w http.ResponseWriter, r *http.Request) {
	cert := peerCert(r)
	if cert == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	clientName := cert.Subject.CommonName
	var ifNoneMatch string
	if values := r.Header.Values("If-None-Match"); len(values) == 1 {
		ifNoneMatch = values[0]
	}

	// The wait outlasts the server's WriteTimeout, past which HTTP/1.1 cuts
	// the response off and HTTP/2 resets the stream. Only this request's write
	// deadline moves; httptest.ResponseRecorder does not support deadlines.
	deadline := time.Now().Add(syncMaxWait)
	_ = http.NewResponseController(w).SetWriteDeadline(deadline.Add(10 * time.Second))
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()

	woken := false
	for {
		// Take the channel before reading the configuration and the store: a
		// reload or a stored certificate that lands between those reads and
		// the wait would otherwise go unnoticed until the deadline. A test
		// checks the order for the configuration read; the store read has no
		// test of its own and is covered only while it shares the
		// certificateView call.
		changed := h.deps.Changes.wait()
		view, err := h.certificateView(r.Context(), clientName)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// The ETag hashes the body this client gets, so it changes only with
		// the client's own view. A global version would let a client observe
		// changes to certificates it does not subscribe to.
		body, err := json.Marshal(view)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		sum := sha256.Sum256(body)
		etag := `"` + base64.RawURLEncoding.EncodeToString(sum[:]) + `"`

		if etag != ifNoneMatch {
			if woken {
				// The client was checked when the request came in; while it
				// waited, the client may have been removed or its identity
				// replaced.
				rec, err := h.deps.DB.Clients.Get(r.Context(), clientName, nil)
				if err != nil || rec.Fingerprint != ca.Fingerprint(cert.Raw) {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", etag)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
			return
		}

		select {
		case <-changed:
			woken = true
			continue
		case <-timer.C:
		case <-h.deps.Done:
			// Answer now rather than hold up the daemon's shutdown.
		case <-r.Context().Done():
			return
		}
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}
}

// certificateView lists, ordered by name, the certificates clientName may
// fetch: those it subscribes to in the running configuration whose stored
// material matches their current specification.
func (h *handlers) certificateView(ctx context.Context, clientName string) ([]proto.CertSummary, error) {
	all, err := h.deps.DB.Certs.List(ctx, nil)
	if err != nil {
		return nil, err
	}

	// Filter by the subscriber list and ensure stored material still matches
	// the current spec. A hot reload must never expose a same-name stale cert.
	cfg := h.deps.CurrentServer()
	subscribed := subscribedSpecs(cfg, clientName)
	view := []proto.CertSummary{}
	for _, c := range all {
		if spec, ok := subscribed[c.Name]; ok && certRecordMatchesSpec(c, cfg, spec) {
			view = append(view, proto.CertSummary{
				Name:        c.Name,
				Fingerprint: c.Fingerprint,
				NotAfter:    c.NotAfter,
			})
		}
	}
	return view, nil
}
