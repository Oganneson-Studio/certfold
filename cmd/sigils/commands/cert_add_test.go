package commands

import (
	"strings"
	"testing"

	"github.com/Oganneson-Studio/sigil/internal/config"
)

// cert add no longer takes --renew-days-before: when a certificate is renewed
// is not configured.
func TestCertAddRejectsRenewDaysBefore(t *testing.T) {
	path := writeManagementTestConfig(t, "  []\n")
	reloader := &fakeServerReloader{}
	stubServerReloader(t, reloader, nil)
	cmd := NewRootCmd()
	cmd.SetArgs([]string{
		"--config", path, "cert", "add", "api-prod",
		"--domains", "api.example.com", "--dns", "route", "--renew-days-before", "30",
	})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "unknown flag: --renew-days-before") {
		t.Fatalf("cert add error = %v, want an unknown flag", err)
	}
	cfg, err := config.LoadServer(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Certificates) != 0 || reloader.calls != 0 {
		t.Fatalf("cert add changed the configuration: %+v, %d reloads", cfg.Certificates, reloader.calls)
	}
}
