package commands

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestJSONIsRefusedWhereNotSupported covers --json given to a command that
// prints nothing for it to shape: the command fails rather than print text a
// script would take for JSON. The test calls the check alone, so no service
// is touched.
func TestJSONIsRefusedWhereNotSupported(t *testing.T) {
	for _, path := range [][]string{
		{"client", "remove"}, {"token", "revoke"}, {"config", "validate"},
		{"service", "install"}, {"service", "uninstall"}, {"service", "start"},
		{"service", "stop"}, {"service", "restart"}, {"service", "status"},
	} {
		for _, asJSON := range []string{"true", "false"} {
			root := NewRootCmd()
			if err := root.PersistentFlags().Set("json", asJSON); err != nil {
				t.Fatal(err)
			}
			cmd, _, err := root.Find(path)
			if err != nil {
				t.Fatal(err)
			}
			if cmd.PreRunE == nil {
				t.Errorf("sigils %s does not check --json", strings.Join(path, " "))
				break
			}
			err = cmd.PreRunE(cmd, nil)
			if want := "--json is not supported by sigils " + strings.Join(path, " "); asJSON == "true" && (err == nil || err.Error() != want) {
				t.Errorf("sigils --json %s: error = %v, want %q", strings.Join(path, " "), err, want)
			}
			if asJSON == "false" && err != nil {
				t.Errorf("sigils %s: error = %v", strings.Join(path, " "), err)
			}
		}
	}

	// Cobra runs the check before the command, which does not read the file.
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	if _, err := runSigilsErr(t, "--json", "--config", missing, "config", "validate"); err == nil || err.Error() != "--json is not supported by sigils config validate" {
		t.Errorf("sigils --json config validate: error = %v", err)
	}
}
