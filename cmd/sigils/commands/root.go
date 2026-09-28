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
		RunE:          runDefaultTUI,
	}

	cmd.PersistentFlags().String("config", "", "path to server.yaml (default: platform-specific)")
	cmd.PersistentFlags().String("ipc", "", "IPC socket path (default: platform-specific)")
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

	return cmd
}
