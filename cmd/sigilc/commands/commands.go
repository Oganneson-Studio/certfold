package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Oganneson-Studio/sigil/internal/version"
)

func newServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the sigilc daemon (used by the system service)",
		RunE:  runServe,
	}
}

func newReloadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reload",
		Short: "Tell the running daemon to re-read client.yaml",
		RunE:  runReload,
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		RunE: func(_ *cobra.Command, _ []string) error {
			fmt.Println("sigilc " + version.String())
			return nil
		},
	}
}

func newEnrollCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Bootstrap this client by exchanging a one-time token for an mTLS certificate",
		RunE:  runEnroll,
	}
	cmd.Flags().String("token", "", "enrollment token issued by sigils (default: $SIGILC_TOKEN, which keeps it off the command line)")
	return cmd
}

func newStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Print current client status (one-shot; for scripts)",
		RunE:  runStatus,
	}
	cmd.Flags().Bool("json", false, "emit machine-readable JSON")
	return cmd
}

func newFetchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "Pull from sigils now and reconcile the outputs before returning",
		RunE:  runFetch,
	}
	cmd.Flags().String("cert", "", "also download the named certificate again; its outputs are rewritten only if they differ")
	return cmd
}
