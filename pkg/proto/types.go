package proto

import "time"

// SyncMaxWait is how long GET /v1/sync holds a request whose If-None-Match
// equals the client's current view before it answers 304. A client must wait
// longer than this for the response, and a proxy between client and server
// needs an idle timeout above 60 seconds.
const SyncMaxWait = 55 * time.Second

// EnrollRequest is the JSON body for POST /v1/enroll.
type EnrollRequest struct {
	Token string `json:"token"`
	CSR   string `json:"csr"` // PEM-encoded PKCS#10 CSR
}

// EnrollResponse is returned on successful POST /v1/enroll. The CA that
// signed ClientCert is the one in the token, which certfoldc saves.
type EnrollResponse struct {
	ClientCert string `json:"client_cert"` // PEM
}

// RenewIdentityRequest asks the server to issue a replacement mTLS client
// certificate. The request itself is authenticated with the current identity.
type RenewIdentityRequest struct {
	CSR string `json:"csr"` // PEM-encoded PKCS#10 CSR
}

// RenewIdentityResponse carries the replacement client certificate. The
// client already owns the corresponding private key used for the CSR.
type RenewIdentityResponse struct {
	ClientCert string `json:"client_cert"` // PEM
}

// CertSummary is one entry in the GET /v1/sync response.
type CertSummary struct {
	Name        string    `json:"name"`
	Fingerprint string    `json:"fingerprint"`
	NotAfter    time.Time `json:"not_after"`
}

// CertBundle is returned by GET /v1/certificates/:name/bundle.
type CertBundle struct {
	Name string `json:"name"`
	// Fingerprint identifies the material, as in CertSummary. It is read from
	// the same database row as the PEM fields, so it matches them even when
	// the certificate was renewed after the client's last sync.
	Fingerprint  string `json:"fingerprint"`
	FullchainPEM string `json:"fullchain_pem"`
	KeyPEM       string `json:"key_pem"`
}
