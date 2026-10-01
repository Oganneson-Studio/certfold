package commands

import (
	"io"
	"strings"
	"testing"
)

// TestUnknownSubcommandFails is the certfoldc side of the certfolds test of the
// same name: `certfoldc service instal` must not exit 0.
func TestUnknownSubcommandFails(t *testing.T) {
	for _, group := range NewRootCmd().Commands() {
		if !group.HasSubCommands() {
			continue
		}
		root := NewRootCmd()
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		root.SetArgs([]string{group.Name(), "no-such-subcommand"})
		if err := root.Execute(); err == nil || !strings.Contains(err.Error(), `unknown command "no-such-subcommand"`) {
			t.Errorf("certfoldc %s no-such-subcommand: error = %v, want an unknown command error", group.Name(), err)
		}
	}
}
