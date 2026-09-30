package commands

import (
	"strings"
	"testing"
)

// TestConfigShowIsGone covers `sigils config show`, which printed the
// configuration after expanding ${VAR}: the DNS provider credentials that
// server.yaml keeps out of the file reached stdout, and with it the terminal
// scrollback and whatever the output is pasted into.
func TestConfigShowIsGone(t *testing.T) {
	path := writeManagementTestConfig(t, "  []\n")
	printed, err := runSigilsErr(t, "--config", path, "config", "show")
	if err == nil || !strings.Contains(err.Error(), `unknown command "show"`) {
		t.Errorf("sigils config show: error = %v, want an unknown command error", err)
	}
	for _, secret := range []string{"expanded-access-key", "expanded-secret-key"} {
		if strings.Contains(printed, secret) {
			t.Errorf("config show printed the value of a ${VAR} credential (%s):\n%s", secret, printed)
		}
	}
}
