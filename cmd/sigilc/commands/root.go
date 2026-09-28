package commands

import (
	"github.com/spf13/cobra"
)

func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sigilc",
		Short: "Sigil Client — pulls certificates from sigils and writes them to disk",
		Long: `sigilc is the Sigil client daemon.

Run without arguments to open the TUI status panel.
Use 'enroll' to bootstrap a new client against a sigils instance.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          runDefaultTUI,
	}

	cmd.PersistentFlags().String("config", "", "path to client.yaml (default: platform-specific)")
	cmd.PersistentFlags().String("ipc", "", "IPC socket path (default: platform-specific)")

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

	return cmd
}
