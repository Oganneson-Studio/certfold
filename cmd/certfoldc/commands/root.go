package commands

import (
	"github.com/spf13/cobra"
)

func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "certfoldc",
		Short: "Certfold Client — pulls certificates from certfolds and writes them to disk",
		Long: `certfoldc is the Certfold client daemon.

Run without arguments to open the TUI status panel.
Use 'enroll' to bootstrap a new client against a certfolds instance.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          runClientTUI,
	}

	cmd.PersistentFlags().String("config", "", "path to client.yaml (default: $CERTFOLDC_CONFIG, else platform-specific)")
	cmd.PersistentFlags().String("ipc", "", "IPC socket path (default: client.ipc_socket in the config, else platform-specific)")

	cmd.AddCommand(
		newServeCmd(),
		newReloadCmd(),
		newVersionCmd(),
		newServiceCmd(),
		newEnrollCmd(),
		newStatusCmd(),
		newFetchCmd(),
		newEventsCmd(),
	)
	failOnUnknownSubcommand(cmd)

	return cmd
}

// failOnUnknownSubcommand makes each command group of root, which runs
// nothing itself, fail on an argument that names none of its subcommands.
// Cobra would answer a mistyped one, such as `certfoldc service instal` in a
// provisioning script, with the help of the group and exit status 0.
func failOnUnknownSubcommand(root *cobra.Command) {
	for _, group := range root.Commands() {
		if group.HasSubCommands() && group.RunE == nil {
			group.Args = cobra.NoArgs
			group.RunE = func(c *cobra.Command, _ []string) error { return c.Help() }
		}
	}
}
