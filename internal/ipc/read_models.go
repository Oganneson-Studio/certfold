package ipc

import (
	"time"

	"github.com/Oganneson-Studio/sigil/internal/store"
)

// CertificateInfo is the read-only certificate metadata exposed over IPC.
type CertificateInfo struct {
	Name        string    `json:"name"`
	CA          string    `json:"ca"`
	Domains     []string  `json:"domains"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"fingerprint"`
	IssuedAt    time.Time `json:"issued_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ClientInfo is the read-only enrolled-client metadata exposed over IPC.
type ClientInfo struct {
	Name           string    `json:"name"`
	Fingerprint    string    `json:"fingerprint"`
	EnrolledAt     time.Time `json:"enrolled_at"`
	LastSeen       time.Time `json:"last_seen"`
	PushEndpoint   string    `json:"push_endpoint"`
	PushConfigured bool      `json:"push_configured"`
}

// TokenInfo is the read-only enrollment-token metadata exposed over IPC.
type TokenInfo struct {
	TokenID   string    `json:"token_id"`
	Name      string    `json:"name"`
	ExpiresAt time.Time `json:"expires_at"`
	UsedAt    time.Time `json:"used_at"`
	CreatedAt time.Time `json:"created_at"`
}

// ServerState is the read-only daemon state exposed over IPC.
type ServerState struct {
	Certs   []*CertificateInfo `json:"certs"`
	Clients []*ClientInfo      `json:"clients"`
	Tokens  []*TokenInfo       `json:"tokens"`
}

func certificateInfos(records []*store.CertRecord) []*CertificateInfo {
	out := make([]*CertificateInfo, 0, len(records))
	for _, record := range records {
		if record == nil {
			continue
		}
		out = append(out, &CertificateInfo{
			Name:        record.Name,
			CA:          record.CA,
			Domains:     append([]string{}, record.Domains...),
			NotAfter:    record.NotAfter,
			Fingerprint: record.Fingerprint,
			IssuedAt:    record.IssuedAt,
			UpdatedAt:   record.UpdatedAt,
		})
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
			Name:           record.Name,
			Fingerprint:    record.Fingerprint,
			EnrolledAt:     record.EnrolledAt,
			LastSeen:       record.LastSeen,
			PushEndpoint:   record.PushEndpoint,
			PushConfigured: record.PushToken != "",
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
