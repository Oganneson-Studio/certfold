package config

import "testing"

func TestCertificateSpecFingerprintTracksMaterialConfiguration(t *testing.T) {
	cfg := &ServerConfig{ACME: ACMESection{CAs: map[string]CAEntry{
		"le": {Directory: "https://acme.example/directory"},
	}}}
	spec := CertificateSpec{
		Name: "api", CA: "le", Domains: []string{"api.example.com"},
		KeyType: "ec256", Subscribers: []string{"web-1"},
	}
	base := CertificateSpecFingerprint(cfg, spec)

	subscriberChange := spec
	subscriberChange.Subscribers = []string{"web-2"}
	if got := CertificateSpecFingerprint(cfg, subscriberChange); got != base {
		t.Fatal("subscriber-only change altered material fingerprint")
	}

	keyChange := spec
	keyChange.KeyType = "rsa2048"
	if got := CertificateSpecFingerprint(cfg, keyChange); got == base {
		t.Fatal("key type change did not alter material fingerprint")
	}

	domainChange := spec
	domainChange.Domains = []string{"api-v2.example.com"}
	if got := CertificateSpecFingerprint(cfg, domainChange); got == base {
		t.Fatal("domain change did not alter material fingerprint")
	}

	nextCfg := *cfg
	nextCfg.ACME.CAs = map[string]CAEntry{"le": {Directory: "https://new.example/directory"}}
	if got := CertificateSpecFingerprint(&nextCfg, spec); got == base {
		t.Fatal("CA directory change did not alter material fingerprint")
	}
}
