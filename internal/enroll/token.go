// Package enroll implements the one-time-token bootstrap protocol that
// exchanges a token for an mTLS client certificate.
package enroll

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/ca"
	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/store"
)

// tokenPayload is the JSON structure embedded inside the opaque token string.
type tokenPayload struct {
	ServerURL string    `json:"server_url"`
	Name      string    `json:"name"`
	TokenID   string    `json:"token_id"`
	Secret    string    `json:"secret"`
	CACert    string    `json:"ca_cert"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Server handles server-side token creation and verification.
type Server struct {
	tokens  *store.TokenRepo
	clients *store.ClientRepo
	miniCA  *ca.MiniCA
}

// NewServer creates a Server.
func NewServer(tokens *store.TokenRepo, clients *store.ClientRepo, miniCA *ca.MiniCA) *Server {
	return &Server{tokens: tokens, clients: clients, miniCA: miniCA}
}

// Create generates a new one-time enrollment token for name with the given TTL.
// name must be a valid client name (config.ValidateClientName); it becomes the
// CN of the enrolled client's certificate.
// Returns the opaque base64url-encoded token string to hand to the client.
func (s *Server) Create(ctx context.Context, serverURL, name string, ttl time.Duration) (string, error) {
	if err := config.ValidateClientName(name); err != nil {
		return "", err
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}

	tokenID := hex.EncodeToString(idBytes)
	secret := hex.EncodeToString(secretBytes)
	expiresAt := time.Now().UTC().Add(ttl)

	payload := tokenPayload{
		ServerURL: serverURL,
		Name:      name,
		TokenID:   tokenID,
		Secret:    secret,
		CACert:    string(s.miniCA.CertPEM()),
		ExpiresAt: expiresAt,
	}
	rec := &store.TokenRecord{
		TokenID:    tokenID,
		Name:       name,
		SecretHash: tokenPayloadHash(&payload),
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now().UTC(),
	}
	if err := s.tokens.Upsert(ctx, rec, nil); err != nil {
		return "", fmt.Errorf("store token: %w", err)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Verify decodes and validates a token string. Returns the client name on success.
// Does NOT mark the token as used — the caller should call MarkUsed after signing.
func (s *Server) Verify(ctx context.Context, tokenStr string) (name string, tokenID string, err error) {
	payload, err := decodeToken(tokenStr)
	if err != nil {
		return "", "", fmt.Errorf("decode: %w", err)
	}

	rec, err := s.tokens.Get(ctx, payload.TokenID, nil)
	if err == sql.ErrNoRows {
		return "", "", fmt.Errorf("invalid token")
	}
	if err != nil {
		return "", "", fmt.Errorf("lookup: %w", err)
	}
	if !rec.UsedAt.IsZero() {
		return "", "", fmt.Errorf("token already used")
	}
	if time.Now().After(rec.ExpiresAt) {
		return "", "", fmt.Errorf("token expired")
	}
	if tokenPayloadHash(payload) != rec.SecretHash {
		return "", "", fmt.Errorf("invalid token")
	}
	return rec.Name, rec.TokenID, nil
}

// SignClientCert signs a DER-encoded CSR for the given client name and records
// the client in the clients table. Returns the signed certificate DER bytes.
func (s *Server) SignClientCert(ctx context.Context, csrDER []byte, name, tokenID string) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	certDER, err := s.miniCA.Sign(csr, name)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	if err := s.tokens.MarkUsed(ctx, tokenID, nil); err != nil {
		return nil, fmt.Errorf("mark used: %w", err)
	}
	fp := ca.Fingerprint(certDER)
	if err := s.clients.Upsert(ctx, &store.ClientRecord{
		Name:        name,
		Fingerprint: fp,
		EnrolledAt:  time.Now().UTC(),
	}, nil); err != nil {
		return nil, fmt.Errorf("record client: %w", err)
	}
	return certDER, nil
}

// DecodeToken base64url-decodes an enrollment token and returns the payload.
// The client uses ServerURL to know which server to POST the CSR to.
func DecodeToken(tokenStr string) (*tokenPayload, error) {
	return decodeToken(tokenStr)
}

// decodeToken base64url-decodes and JSON-unmarshals a token string.
func decodeToken(tokenStr string) (*tokenPayload, error) {
	raw, err := base64.RawURLEncoding.DecodeString(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("base64: %w", err)
	}
	var p tokenPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("json: %w", err)
	}
	return &p, nil
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func tokenPayloadHash(p *tokenPayload) string {
	return sha256hex(p.Secret + "\x00" + p.ServerURL + "\x00" + p.Name + "\x00" + p.CACert)
}
