package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Oganneson-Studio/sigil/internal/version"
)

func runDefaultTUI(cmd *cobra.Command, args []string) error {
	return runServerTUI(cmd, args)
}

func newServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the sigils daemon (used by the system service)",
		RunE:  runServe,
	}
}

func newReloadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reload",
		Short: "Validate and apply reloadable server.yaml changes",
		RunE:  runReload,
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		RunE: func(_ *cobra.Command, _ []string) error {
			fmt.Printf("sigils %s (commit %s, built %s)\n", version.Version, version.Commit, version.BuildDate)
			return nil
		},
	}
}

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Inspect and validate server.yaml",
	}
	cmd.AddCommand(
		&cobra.Command{Use: "validate", Short: "Parse and validate server.yaml without starting the daemon", RunE: runConfigValidate},
		&cobra.Command{Use: "show", Short: "Print the effective configuration (with defaults applied)", RunE: runConfigShow},
	)
	return cmd
}

func newCertCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Manage certificates",
	}

	add := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a new certificate to server.yaml",
		Args:  cobra.ExactArgs(1),
		RunE:  runCertAdd,
	}
	add.Flags().StringSlice("domains", nil, "domain list (repeat or comma-separated)")
	add.Flags().String("ca", "", "CA name (must exist in acme.cas)")
	add.Flags().String("dns", "", "DNS provider name (must exist in dns_providers)")
	add.Flags().String("key-type", "ec256", "key type: rsa2048 | rsa4096 | ec256 | ec384")
	add.Flags().Int("renew-days-before", 30, "days before expiry to renew")
	add.Flags().StringSlice("subscribers", nil, "client names allowed to subscribe")
	_ = add.MarkFlagRequired("domains")
	_ = add.MarkFlagRequired("dns")

	cmd.AddCommand(
		&cobra.Command{Use: "list", Short: "List all certificates", RunE: runCertList},
		&cobra.Command{Use: "show <name>", Short: "Show certificate details", Args: cobra.ExactArgs(1), RunE: runCertShow},
		add,
		&cobra.Command{Use: "remove <name>", Short: "Remove a certificate from server.yaml", Args: cobra.ExactArgs(1), RunE: runCertRemove},
		&cobra.Command{Use: "renew <name>", Short: "Force immediate renewal", Args: cobra.ExactArgs(1), RunE: runCertRenew},
	)
	return cmd
}

func newClientCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "client",
		Short: "Manage enrolled clients",
	}
	cmd.AddCommand(
		&cobra.Command{Use: "list", Short: "List all enrolled clients", RunE: runClientList},
		&cobra.Command{Use: "show <name>", Short: "Show client details", Args: cobra.ExactArgs(1), RunE: runClientShow},
		&cobra.Command{Use: "remove <name>", Short: "Remove a client and revoke its mTLS certificate", Args: cobra.ExactArgs(1), RunE: runClientRemove},
	)
	return cmd
}

func newTokenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Manage one-time enrollment tokens",
	}

	create := &cobra.Command{
		Use:   "create",
		Short: "Create an enrollment token and print one-line install commands",
		RunE:  runTokenCreate,
	}
	create.Flags().String("name", "", "client name (must be unique)")
	create.Flags().Duration("expires", 0, "token lifetime (default 1h)")
	_ = create.MarkFlagRequired("name")

	cmd.AddCommand(
		create,
		&cobra.Command{Use: "list", Short: "List active enrollment tokens", RunE: runTokenList},
		&cobra.Command{Use: "revoke <id>", Short: "Revoke an unused enrollment token", Args: cobra.ExactArgs(1), RunE: runTokenRevoke},
	)
	return cmd
}
