package config

import (
	"strings"
	"testing"
)

const outputModeClientYAML = `client:
  name: web-1
  server_url: https://sigil.example.com:8443
certificates:
  web:
    outputs:
      - format: pem-key
        path: /etc/ssl/web.key
        mode: MODE
`

// mode is read in octal as chmod takes it, with or without a leading 0 or
// 0o. YAML alone reads 400 as decimal, which is 0o620, and 440 as 0o670, and
// both are valid modes that let the group write the key.
func TestOutputModeIsOctal(t *testing.T) {
	t.Setenv("SIGIL_TEST_MODE", "640")
	for _, tt := range []struct {
		text string
		want FileMode
	}{
		{"400", 0o400},
		{"440", 0o440},
		{"600", 0o600},
		{"0600", 0o600},
		{"0o640", 0o640},
		{`"0600"`, 0o600},
		{"'644'", 0o644},
		// The text of the variable, not what YAML would make of it.
		{"${SIGIL_TEST_MODE}", 0o640},
		{"${SIGIL_TEST_UNSET:-0440}", 0o440},
		{"~", 0},
	} {
		cfg, err := ParseClient([]byte(strings.Replace(outputModeClientYAML, "MODE", tt.text, 1)))
		if err != nil {
			t.Errorf("mode: %s rejected: %v", tt.text, err)
			continue
		}
		if got := cfg.Certificates["web"].Outputs[0].Mode; got != tt.want {
			t.Errorf("mode: %s = %#o, want %#o", tt.text, got, tt.want)
		}
	}
}

func TestOutputModeRejectsWhatIsNotOctal(t *testing.T) {
	for _, tt := range []struct {
		text, want string
	}{
		{"648", `mode "648" is not an octal file mode`},
		{"0x1a4", `mode "0x1a4" is not an octal file mode`},
		{"-0600", `mode "-0600" is not an octal file mode`},
		{"rw-r-----", `mode "rw-r-----" is not an octal file mode`},
		{"[0600]", `mode "" is not an octal file mode`},
		{"1000", "certificates.web.outputs[0].mode: must be a valid octal file mode (got 01000)"},
	} {
		_, err := ParseClient([]byte(strings.Replace(outputModeClientYAML, "MODE", tt.text, 1)))
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("mode: %s: error = %v, want %s", tt.text, err, tt.want)
		}
	}
}
