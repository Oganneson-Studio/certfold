package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Oganneson-Studio/sigil/internal/version"
)

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
		RunE: func(cmd *cobra.Command, _ []string) error {
			if asJSON, _ := cmd.Root().PersistentFlags().GetBool("json"); asJSON {
				return printJSON(struct {
					Version string `json:"version"`
					Commit  string `json:"commit,omitempty"`
				}{version.Version, version.Commit})
			}
			fmt.Println("sigils " + version.String())
			return nil
		},
	}
}

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Validate server.yaml",
	}
	cmd.AddCommand(
		&cobra.Command{Use: "validate", Short: "Parse and validate server.yaml without starting the daemon", RunE: runConfigValidate},
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
	add.Flags().StringSlice("subscribers", nil, "client names allowed to subscribe")
	_ = add.MarkFlagRequired("domains")
	_ = add.MarkFlagRequired("dns")

	cmd.AddCommand(
		&cobra.Command{Use: "list", Short: "List configured certificates and their issuance state", RunE: runCertList},
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
	create.Flags().String("name", "", "client name; the name of an enrolled client, or one with an unused token, needs --replace")
	create.Flags().Duration("expires", 0, "token lifetime, at most 168h (default 1h)")
	create.Flags().Bool("replace", false, "create a token for the name of an enrolled client, or one with an unused token, and revoke "+
		"the unused tokens: the host that enrolls with it replaces the client, takes over its certificates and locks the enrolled host out")
	_ = create.MarkFlagRequired("name")

	cmd.AddCommand(
		create,
		&cobra.Command{Use: "list", Short: "List enrollment tokens: unused, used or expired", RunE: runTokenList},
		&cobra.Command{Use: "revoke <id>", Short: "Revoke an unused enrollment token", Args: cobra.ExactArgs(1), RunE: runTokenRevoke},
	)
	return cmd
}
