package enroll

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Oganneson-Studio/sigil/internal/config"
)

// Guard for merging D (config.FileMode reads mode in octal) together with A
// (SaveIdentity replaces only the identity key). SaveIdentity runs at enroll
// and at every identity renewal of the daemon. With D alone, the map round
// trip of SaveIdentity rewrites "mode: 0640" as "mode: 416", which FileMode
// reads back as 0o416: the private key becomes readable and writable by
// other users. Fails on D alone; passes on main (e2ef622), and must pass on
// D+A. The two cases are the spellings main already accepts.
func TestSaveIdentityKeepsOutputModes(t *testing.T) {
	for _, text := range []string{"0640", "0o640"} {
		path := filepath.Join(t.TempDir(), "client.yaml")
		raw := "client:\n  name: web-1\n  server_url: https://sigil.example.com:8443\n" +
			"certificates:\n  web:\n    outputs:\n      - format: pem-key\n        path: /etc/ssl/web.key\n        mode: " + text + "\n"
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		before, err := config.LoadClient(path)
		if err != nil {
			t.Fatalf("mode: %s: load before: %v", text, err)
		}
		if err := SaveIdentity(path, "", "", ""); err != nil {
			t.Fatalf("mode: %s: SaveIdentity: %v", text, err)
		}
		after, err := config.LoadClient(path)
		if err != nil {
			t.Fatalf("mode: %s: load after SaveIdentity: %v", text, err)
		}
		if got, want := after.Certificates["web"].Outputs[0].Mode, before.Certificates["web"].Outputs[0].Mode; got != want {
			written, _ := os.ReadFile(path)
			t.Errorf("mode: %s = %#o after SaveIdentity, was %#o; file now reads:\n%s", text, got, want, strings.TrimSpace(string(written)))
		}
	}
}
