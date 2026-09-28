package ipc

import (
	"time"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/logging"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

// This file defines the request and response bodies of the IPC API. The read
// models are explicit DTOs: they never carry certificate private keys or
// enrollment-token secret hashes.

// CertificateInfo is the read-only certificate metadata exposed over IPC.
type CertificateInfo struct {
	Name          string    `json:"name"`
	CA            string    `json:"ca"`
	Domains       []string  `json:"domains"`
	NotAfter      time.Time `json:"not_after"`
	Fingerprint   string    `json:"fingerprint"`
	IssuedAt      time.Time `json:"issued_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	State         string    `json:"state"`
	Failures      int       `json:"failures"`
	LastError     string    `json:"last_error"`
	LastAttemptAt time.Time `json:"last_attempt_at"`
	NextAttemptAt time.Time `json:"next_attempt_at"`
}

// Values of CertificateInfo.State. When several apply, the first listed wins.
const (
	CertStateIssuing = "issuing" // an issuance holds the certificate's lock, even while waiting for a slot
	CertStateBackoff = "backoff" // NextAttemptAt is in the future
	CertStateValid   = "valid"   // the stored certificate matches the running configuration
	CertStatePending = "pending" // none of the above
)

// RenewCertRequest is the body of POST /ipc/v1/certs/renew.
type RenewCertRequest struct {
	Name string `json:"name"`
}

// ClientInfo is the read-only enrolled-client metadata exposed over IPC.
type ClientInfo struct {
	Name        string    `json:"name"`
	Fingerprint string    `json:"fingerprint"`
	EnrolledAt  time.Time `json:"enrolled_at"`
	LastSeen    time.Time `json:"last_seen"`
}

// TokenInfo is the read-only enrollment-token metadata exposed over IPC.
type TokenInfo struct {
	TokenID   string    `json:"token_id"`
	Name      string    `json:"name"`
	ExpiresAt time.Time `json:"expires_at"`
	UsedAt    time.Time `json:"used_at"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateTokenRequest is the body of POST /ipc/v1/tokens.
type CreateTokenRequest struct {
	Name string        `json:"name"`
	TTL  time.Duration `json:"ttl"`
}

// CreateTokenResponse is returned by POST /ipc/v1/tokens. ServerURL is the
// base URL the token is bound to. PublicURLConfigured reports whether it
// comes from server.public_url rather than being derived from server.listen.
type CreateTokenResponse struct {
	Token               string `json:"token"`
	ServerURL           string `json:"server_url"`
	PublicURLConfigured bool   `json:"public_url_configured"`
}

// ClientState is the runtime status returned by a sigilc daemon. Certs lists
// the certificates in its store in name order, and is never null.
type ClientState struct {
	Name       string            `json:"name"`
	ServerURL  string            `json:"server_url"`
	Online     bool              `json:"online"`
	LastPullAt time.Time         `json:"last_pull_at,omitempty"`
	LastError  string            `json:"last_error,omitempty"`
	Certs      []ClientCertState `json:"certs"`
}

// ClientCertState is a certificate in the store of sigilc. Outputs is the
// number of outputs client.yaml configures for it, and OnChange reports
// whether client.yaml configures an on_change program for it. HookPending
// reports that the program has yet to succeed since the certificate or one
// of its outputs changed.
type ClientCertState struct {
	Name        string    `json:"name"`
	Fingerprint string    `json:"fingerprint"`
	NotAfter    time.Time `json:"not_after"`
	Outputs     int       `json:"outputs"`
	OnChange    bool      `json:"on_change"`
	HookPending bool      `json:"hook_pending"`
}

// EventsPage is returned by GET /ipc/v1/events. Events holds the events with
// a Seq greater than the after parameter, oldest first, and is never null.
// Seq starts over when the daemon restarts, so a caller that polls with the
// last Seq it has seen must also compare Started: when it changes, the caller
// drops the events it has and asks again with after=0.
type EventsPage struct {
	Started time.Time       `json:"started"`
	Events  []logging.Event `json:"events"`
}

// FetchClientRequest is the body of POST /ipc/v1/client/fetch. The fetch is a
// full pull: sigilc downloads the certificates whose fingerprints changed,
// reconciles every output and runs the pending on_change programs before it
// answers. A non-empty name also downloads that certificate again; its
// outputs are rewritten only if they differ from it.
type FetchClientRequest struct {
	Name string `json:"name,omitempty"`
}

// certificateInfos lists the certificates of cfg in configuration order.
// Stored material is reported only when its spec fingerprint matches the
// running configuration, so it is the material clients can fetch. Records of
// certificates that are no longer configured are left out.
func certificateInfos(cfg *config.ServerConfig, records []*store.CertRecord, statuses []*store.IssuanceStatus, issuing func(string) bool, now time.Time) []*CertificateInfo {
	stored := make(map[string]*store.CertRecord, len(records))
	for _, record := range records {
		stored[record.Name] = record
	}
	attempts := make(map[string]*store.IssuanceStatus, len(statuses))
	for _, status := range statuses {
		attempts[status.Name] = status
	}
	out := make([]*CertificateInfo, 0, len(cfg.Certificates))
	for _, spec := range cfg.Certificates {
		info := &CertificateInfo{
			Name:    spec.Name,
			CA:      spec.CA,
			Domains: append([]string{}, spec.Domains...),
		}
		record := stored[spec.Name]
		matched := record != nil && record.SpecFingerprint == config.CertificateSpecFingerprint(cfg, spec)
		if matched {
			info.NotAfter = record.NotAfter
			info.Fingerprint = record.Fingerprint
			info.IssuedAt = record.IssuedAt
			info.UpdatedAt = record.UpdatedAt
		}
		if status := attempts[spec.Name]; status != nil {
			info.Failures = status.Failures
			info.LastError = status.LastError
			info.LastAttemptAt = status.LastAttemptAt
			info.NextAttemptAt = status.NextAttemptAt
		}
		switch {
		case issuing(spec.Name):
			info.State = CertStateIssuing
		case info.NextAttemptAt.After(now):
			info.State = CertStateBackoff
		case matched:
			info.State = CertStateValid
		default:
			info.State = CertStatePending
		}
		out = append(out, info)
	}
	return out
}

func clientInfos(records []*store.ClientRecord) []*ClientInfo {
	out := make([]*ClientInfo, 0, len(records))
	for _, record := range records {
		if record == nil {
			continue
		}
		out = append(out, &ClientInfo{
			Name:        record.Name,
			Fingerprint: record.Fingerprint,
			EnrolledAt:  record.EnrolledAt,
			LastSeen:    record.LastSeen,
		})
	}
	return out
}

func tokenInfos(records []*store.TokenRecord) []*TokenInfo {
	out := make([]*TokenInfo, 0, len(records))
	for _, record := range records {
		if record == nil {
			continue
		}
		out = append(out, &TokenInfo{
			TokenID:   record.TokenID,
			Name:      record.Name,
			ExpiresAt: record.ExpiresAt,
			UsedAt:    record.UsedAt,
			CreatedAt: record.CreatedAt,
		})
	}
	return out
}
