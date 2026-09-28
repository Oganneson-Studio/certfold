package ipc

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Oganneson-Studio/sigil/internal/config"
)

func notIssuing(string) bool { return false }

// TestCertificateInfosCopySubscribers covers the subscribers of each
// configured certificate: [] for none, and a copy, so the answer never
// shares memory with the running configuration.
func TestCertificateInfosCopySubscribers(t *testing.T) {
	subscribed := config.CertificateSpec{Name: "api-prod", CA: "le", Domains: []string{"api.example.com"}, KeyType: "ec256",
		Subscribers: []string{"web-1", "web-2"}}
	unsubscribed := config.CertificateSpec{Name: "internal", CA: "le", Domains: []string{"internal.example.com"}, KeyType: "ec256"}
	cfg := testCertConfig(subscribed, unsubscribed)

	infos := certificateInfos(cfg, nil, nil, notIssuing, time.Now())
	raw, err := json.Marshal(infos)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"name":"api-prod","ca":"le","domains":["api.example.com"],"subscribers":["web-1","web-2"]`, `"subscribers":[]`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("answer lacks %s: %s", want, raw)
		}
	}
	infos[0].Subscribers[0] = "changed"
	if cfg.Certificates[0].Subscribers[0] != "web-1" {
		t.Fatal("the answer shares the subscribers of the running configuration")
	}
}
