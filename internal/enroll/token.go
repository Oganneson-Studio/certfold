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
	"errors"
	"fmt"
	"time"

	"github.com/Oganneson-Studio/certfold/internal/ca"
	"github.com/Oganneson-Studio/certfold/internal/config"
	"github.com/Oganneson-Studio/certfold/internal/store"
)

// Token is what an enrollment token carries: its string is this structure
// in JSON, base64url-encoded.
type Token struct {
	ServerURL string    `json:"server_url"`
	Name      string    `json:"name"`
	TokenID   string    `json:"token_id"`
	Secret    string    `json:"secret"`
	CACert    string    `json:"ca_cert"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Server handles server-side token creation and verification.
type Server struct {
	db     *store.DB
	miniCA *ca.MiniCA
}

// NewServer creates a Server that keeps tokens and clients in db.
func NewServer(db *store.DB, miniCA *ca.MiniCA) *Server {
	return &Server{db: db, miniCA: miniCA}
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

	payload := Token{
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
	if err := s.db.Tokens.Upsert(ctx, rec, nil); err != nil {
		return "", fmt.Errorf("store token: %w", err)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Reasons that Verify and SignClientCert refuse a token. ErrTokenUsed and
// ErrTokenExpired come only for a token whose secret checks out, so they tell
// nothing to anyone who does not hold the whole token; any other flaw of a
// token is ErrInvalidToken.
var (
	ErrInvalidToken = errors.New("invalid token")
	ErrTokenUsed    = errors.New("enrollment token was already used")
	ErrTokenExpired = errors.New("enrollment token has expired")
)

// Verify decodes and validates a token string. Returns the client name and
// token ID on success, and with ErrTokenUsed and ErrTokenExpired as well.
// Does NOT mark the token as used: SignClientCert does.
func (s *Server) Verify(ctx context.Context, tokenStr string) (name string, tokenID string, err error) {
	payload, err := DecodeToken(tokenStr)
	if err != nil {
		return "", "", ErrInvalidToken
	}

	rec, err := s.db.Tokens.Get(ctx, payload.TokenID, nil)
	if err == sql.ErrNoRows {
		return "", "", ErrInvalidToken
	}
	if err != nil {
		return "", "", fmt.Errorf("look up token: %w", err)
	}
	if tokenPayloadHash(payload) != rec.SecretHash {
		return "", "", ErrInvalidToken
	}
	if !rec.UsedAt.IsZero() {
		return rec.Name, rec.TokenID, ErrTokenUsed
	}
	if time.Now().After(rec.ExpiresAt) {
		return rec.Name, rec.TokenID, ErrTokenExpired
	}
	return rec.Name, rec.TokenID, nil
}

// SignClientCert signs csr for the given client name, consumes the token and
// records the client in the clients table. Returns the signed certificate DER
// bytes.
func (s *Server) SignClientCert(ctx context.Context, csr *x509.CertificateRequest, name, tokenID string) ([]byte, error) {
	certDER, err := s.miniCA.Sign(csr, name)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	// The token is consumed only together with the record of its client, so
	// an enrollment that fails to record it leaves the token for another
	// attempt. The token goes first: of two enrollments with one token, the
	// second fails there, before it could replace the fingerprint of the
	// first.
	tx, err := s.db.BeginTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.db.Tokens.MarkUsed(ctx, tokenID, tx); errors.Is(err, store.ErrTokenAlreadyUsed) {
		// Another enrollment with the token got there since Verify.
		return nil, ErrTokenUsed
	} else if err != nil {
		return nil, fmt.Errorf("mark used: %w", err)
	}
	if err := s.db.Clients.Upsert(ctx, &store.ClientRecord{
		Name:        name,
		Fingerprint: ca.Fingerprint(certDER),
		EnrolledAt:  time.Now().UTC(),
	}, tx); err != nil {
		return nil, fmt.Errorf("record client: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return certDER, nil
}

// DecodeToken base64url-decodes and JSON-unmarshals a token string, and checks
// the client name and the server URL it carries under the rules Create and
// server.public_url follow. certfoldc writes both to client.yaml and prints
// them, so a token that another program made must not bring it control
// characters.
func DecodeToken(tokenStr string) (*Token, error) {
	raw, err := base64.RawURLEncoding.DecodeString(tokenStr)
	if err != nil {
		return nil, fmt.Errorf("base64: %w", err)
	}
	var p Token
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("json: %w", err)
	}
	if err := config.ValidateClientName(p.Name); err != nil {
		return nil, err
	}
	if err := config.ValidatePublicURL(p.ServerURL); err != nil {
		return nil, fmt.Errorf("server URL: %w", err)
	}
	return &p, nil
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func tokenPayloadHash(p *Token) string {
	return sha256hex(p.Secret + "\x00" + p.ServerURL + "\x00" + p.Name + "\x00" + p.CACert)
}
