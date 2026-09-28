package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// CertificateSpecFingerprint identifies the configuration that determines
// certificate key material. Subscriber changes intentionally do not alter it.
func CertificateSpecFingerprint(cfg *ServerConfig, spec CertificateSpec) string {
	ca := CAEntry{}
	if cfg != nil {
		ca = cfg.ACME.CAs[spec.CA]
	}
	payload, _ := json.Marshal(struct {
		CA        string   `json:"ca"`
		Directory string   `json:"directory"`
		Domains   []string `json:"domains"`
		KeyType   string   `json:"key_type"`
	}{
		CA:        spec.CA,
		Directory: ca.Directory,
		Domains:   spec.Domains,
		KeyType:   spec.KeyType,
	})
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}
