package commands

import (
	"github.com/spf13/cobra"
)

func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sigils",
		Short: "Sigil Server — central ACME issuer and certificate distributor",
		Long: `sigils is the Sigil server daemon and management tool.

Run without arguments to open the TUI management panel.
Use subcommands to manage certificates, clients, and enrollment tokens.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          runServerTUI,
	}

	cmd.PersistentFlags().String("config", "", "path to server.yaml (default: $SIGILS_CONFIG, else platform-specific)")
	cmd.PersistentFlags().String("ipc", "", "IPC socket path (default: server.ipc_socket in the config, else platform-specific)")
	cmd.PersistentFlags().Bool("json", false, "emit machine-readable JSON output")

	cmd.AddCommand(
		newServeCmd(),
		newReloadCmd(),
		newVersionCmd(),
		newServiceCmd(),
		newConfigCmd(),
		newCertCmd(),
		newClientCmd(),
		newTokenCmd(),
		newEventsCmd(),
	)
	failOnUnknownSubcommand(cmd)

	return cmd
}

// failOnUnknownSubcommand makes each command group of root, which runs
// nothing itself, fail on an argument that names none of its subcommands.
// Cobra would answer a mistyped one, such as `sigils service instal` in a
// provisioning script, with the help of the group and exit status 0.
func failOnUnknownSubcommand(root *cobra.Command) {
	for _, group := range root.Commands() {
		if group.HasSubCommands() && group.RunE == nil {
			group.Args = cobra.NoArgs
			group.RunE = func(c *cobra.Command, _ []string) error { return c.Help() }
		}
	}
}
