package commands

import (
	"io"
	"strings"
	"testing"
)

// TestUnknownSubcommandFails covers a mistyped subcommand of a command group,
// such as `certfolds service instal` in a provisioning script. Cobra answers a
// group that has no RunE with its help and a nil error, so the script went on
// as if the service were installed.
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
			t.Errorf("certfolds %s no-such-subcommand: error = %v, want an unknown command error", group.Name(), err)
		}
	}
}
