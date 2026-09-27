package proto

import "time"

// EnrollRequest is the JSON body for POST /v1/enroll.
type EnrollRequest struct {
	Token string `json:"token"`
	CSR   string `json:"csr"` // PEM-encoded PKCS#10 CSR
}

// EnrollResponse is returned on successful POST /v1/enroll.
type EnrollResponse struct {
	CACert     string `json:"ca_cert"`     // PEM
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

// CertSummary is one entry in the GET /v1/certificates response.
type CertSummary struct {
	Name        string    `json:"name"`
	Fingerprint string    `json:"fingerprint"`
	NotAfter    time.Time `json:"not_after"`
}

// CertBundle is returned by GET /v1/certificates/:name/bundle.
type CertBundle struct {
	Name         string `json:"name"`
	FullchainPEM string `json:"fullchain_pem"`
	KeyPEM       string `json:"key_pem"`
}

// HeartbeatRequest is the JSON body for POST /v1/heartbeat.
type HeartbeatRequest struct {
	Version     string `json:"version,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"` // current cert fingerprint the client holds
}

// PushNotify is the body for POST /v1/push/notify (client side).
type PushNotify struct {
	CertName string `json:"cert_name"`
}
