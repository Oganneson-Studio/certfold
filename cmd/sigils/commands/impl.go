package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/spf13/cobra"

	"github.com/Oganneson-Studio/sigil/internal/api"
	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/logging"
	"github.com/Oganneson-Studio/sigil/internal/server"
	internalsvc "github.com/Oganneson-Studio/sigil/internal/service"
	tuiserver "github.com/Oganneson-Studio/sigil/internal/tui/server"
)

// ---------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------

func runServe(cmd *cobra.Command, _ []string) error {
	cfgPath := serverConfigPath(cmd)
	return internalsvc.Run(serverSvcConfig(cmd), func(ctx context.Context, logs logging.Logs) error {
		return server.Run(ctx, cfgPath, logs)
	})
}

// ---------------------------------------------------------------------------
// reload
// ---------------------------------------------------------------------------

type serverReloadResult struct {
	Reloaded bool `json:"reloaded"`
}

func runReload(cmd *cobra.Command, _ []string) error {
	c, err := dialReloadServer(cmd)
	if err != nil {
		return fmt.Errorf("ipc unavailable: %w", err)
	}
	if err := c.ReloadServer(commandContext(cmd)); err != nil {
		return err
	}
	if asJSON, _ := cmd.Root().PersistentFlags().GetBool("json"); asJSON {
		return printJSON(serverReloadResult{Reloaded: true})
	}
	fmt.Println("server configuration reloaded")
	return nil
}

func dialReloadServer(cmd *cobra.Command) (serverReloader, error) {
	path := serverIPCSocket(cmd)
	c, err := dialServerReloader(path)
	if err != nil {
		return nil, fmt.Errorf(
			"connect to %q: %w; if server.ipc_socket changed on disk, retry with --ipc set to the running daemon's current socket",
			path, err,
		)
	}
	return c, nil
}

// ---------------------------------------------------------------------------
// config validate
// ---------------------------------------------------------------------------

func runConfigValidate(cmd *cobra.Command, _ []string) error {
	_, err := config.LoadServer(serverConfigPath(cmd))
	if err != nil {
		return err
	}
	fmt.Println("ok")
	return nil
}

// ---------------------------------------------------------------------------
// cert list / show
// ---------------------------------------------------------------------------

func runCertList(cmd *cobra.Command, _ []string) error {
	asJSON, _ := cmd.Root().PersistentFlags().GetBool("json")
	c, err := ipc.NewClient(serverIPCSocket(cmd))
	if err != nil {
		return fmt.Errorf("ipc unavailable: %w", err)
	}
	certs, err := c.ListCerts(commandContext(cmd))
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(certificateDetailList(certs))
	}
	// Neither certificate names nor domain lists are bounded, so the columns
	// fit what they hold.
	table := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "NAME\tCA\tDOMAINS\tSTATE\tNOT AFTER\tRENEW AT")
	for _, cert := range certs {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\n",
			cert.Name, cert.CA, strings.Join(cert.Domains, ","), cert.State,
			formatTime(cert.NotAfter, "2006-01-02"), formatRenewAt(cert, "2006-01-02"))
	}
	return table.Flush()
}

func runCertShow(cmd *cobra.Command, args []string) error {
	asJSON, _ := cmd.Root().PersistentFlags().GetBool("json")
	c, err := ipc.NewClient(serverIPCSocket(cmd))
	if err != nil {
		return fmt.Errorf("ipc unavailable: %w", err)
	}
	certs, err := c.ListCerts(commandContext(cmd))
	if err != nil {
		return err
	}
	for _, cert := range certs {
		if cert.Name == args[0] {
			if asJSON {
				return printJSON(newCertificateDetails(cert))
			}
			lastError := cert.LastError
			if lastError == "" {
				lastError = "-"
			}
			subscribers := strings.Join(cert.Subscribers, ", ")
			if subscribers == "" {
				subscribers = "-"
			}
			fmt.Printf("Name:         %s\n", cert.Name)
			fmt.Printf("CA:           %s\n", cert.CA)
			fmt.Printf("Domains:      %s\n", strings.Join(cert.Domains, ", "))
			fmt.Printf("Subscribers:  %s\n", subscribers)
			fmt.Printf("Not After:    %s\n", formatTime(cert.NotAfter, "2006-01-02"))
			fmt.Printf("Renew At:     %s\n", formatRenewAt(cert, timeLayout))
			fmt.Printf("State:        %s\n", cert.State)
			fmt.Printf("Failures:     %d\n", cert.Failures)
			fmt.Printf("Last Error:   %s\n", lastError)
			fmt.Printf("Next Attempt: %s\n", formatTime(cert.NextAttemptAt, timeLayout))
			return nil
		}
	}
	return fmt.Errorf("cert %q not found", args[0])
}

// ---------------------------------------------------------------------------
// client list
// ---------------------------------------------------------------------------

func runClientList(cmd *cobra.Command, _ []string) error {
	asJSON, _ := cmd.Root().PersistentFlags().GetBool("json")
	c, err := ipc.NewClient(serverIPCSocket(cmd))
	if err != nil {
		return fmt.Errorf("ipc unavailable: %w", err)
	}
	clients, err := c.ListClients(commandContext(cmd))
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(clientDetailList(clients))
	}
	// Names run to 63 characters and fingerprints to 71, so the columns fit
	// what they hold.
	table := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "NAME\tFINGERPRINT\tLAST SEEN")
	for _, cl := range clients {
		lastSeen := "never"
		if !cl.LastSeen.IsZero() {
			lastSeen = formatTime(cl.LastSeen, "2006-01-02 15:04")
		}
		fmt.Fprintf(table, "%s\t%s\t%s\n", cl.Name, cl.Fingerprint, lastSeen)
	}
	return table.Flush()
}

func runClientRemove(cmd *cobra.Command, args []string) error {
	c, err := ipc.NewClient(serverIPCSocket(cmd))
	if err != nil {
		return fmt.Errorf("ipc unavailable: %w", err)
	}
	name := args[0]
	if err := c.DeleteClient(commandContext(cmd), name); err != nil {
		return err
	}
	fmt.Printf("client %q removed\n", name)

	// The host keeps the private keys of the certificates it fetched. When
	// it is removed because it may be compromised, only new certificates
	// take them from it. The removal stands whether or not they are listed.
	certs, err := c.ListCerts(commandContext(cmd))
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: cannot list the certificates %q subscribes to: %v\n", name, err)
		return nil
	}
	var subscribed []string
	for _, cert := range certs {
		if slices.Contains(cert.Subscribers, name) {
			subscribed = append(subscribed, cert.Name)
		}
	}
	if len(subscribed) > 0 {
		fmt.Printf("its host keeps the private keys of the certificates it subscribes to; if it may be compromised, renew them:\n")
		for _, cert := range subscribed {
			fmt.Printf("  sigils cert renew %s\n", cert)
		}
		fmt.Println("the old certificates and keys stay valid until they expire: renewing does not revoke them")
	}
	return nil
}

// ---------------------------------------------------------------------------
// token create / list / revoke
// ---------------------------------------------------------------------------

// tokenCreateResult is what token create prints with --json.
type tokenCreateResult struct {
	Token          string    `json:"token"`
	TokenID        string    `json:"token_id"`
	ExpiresAt      time.Time `json:"expires_at"`
	Revoked        int       `json:"revoked,omitempty"`
	InstallSh      string    `json:"install_sh"`
	InstallWindows string    `json:"install_ps1"`
}

func runTokenCreate(cmd *cobra.Command, _ []string) error {
	name, _ := cmd.Flags().GetString("name")
	ttl, _ := cmd.Flags().GetDuration("expires")
	replace, _ := cmd.Flags().GetBool("replace")
	if ttl == 0 {
		ttl = time.Hour
	}

	// The running daemon owns the store and the mini-CA, and binds the token
	// to the public URL of the configuration it runs.
	c, err := ipc.NewClient(serverIPCSocket(cmd))
	if err != nil {
		return fmt.Errorf("ipc unavailable: %w", err)
	}
	created, err := c.CreateToken(commandContext(cmd), ipc.CreateTokenRequest{Name: name, TTL: ttl, Replace: replace})
	if errors.Is(err, ipc.ErrReplaceRequired) {
		return fmt.Errorf("create token: %w; to create it anyway, add --replace, which also revokes the unused tokens of %q", err, name)
	}
	if err != nil {
		return fmt.Errorf("create token: %w", err)
	}
	// Without public_url the URL is derived from server.listen and may not be
	// reachable by clients.
	if !created.PublicURLConfigured {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: server.public_url is not set; install URL may be unreachable (%s). Set server.public_url in server.yaml.\n", created.ServerURL)
	}

	sh, ps1 := api.InstallCommands(created.ServerURL, created.Token)
	out := cmd.OutOrStdout()
	if asJSON, _ := cmd.Root().PersistentFlags().GetBool("json"); asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(tokenCreateResult{
			Token:          created.Token,
			TokenID:        created.TokenID,
			ExpiresAt:      created.ExpiresAt,
			Revoked:        created.Revoked,
			InstallSh:      sh,
			InstallWindows: ps1,
		})
	}
	if created.Revoked > 0 {
		fmt.Fprintf(out, "Revoked:  %d unused token(s) for %q\n", created.Revoked, name)
	}
	fmt.Fprintf(out, "Token ID: %s\n", created.TokenID)
	fmt.Fprintf(out, "Expires:  %s\n", formatTime(created.ExpiresAt, timeLayout))
	fmt.Fprintf(out, "Token: %s\n\n", created.Token)
	fmt.Fprintln(out, "Install (Linux/macOS):")
	fmt.Fprintf(out, "  %s\n\n", sh)
	fmt.Fprintln(out, "Install (Windows, elevated PowerShell):")
	fmt.Fprintf(out, "  %s\n", ps1)
	return nil
}

func runTokenList(cmd *cobra.Command, _ []string) error {
	asJSON, _ := cmd.Root().PersistentFlags().GetBool("json")
	c, err := ipc.NewClient(serverIPCSocket(cmd))
	if err != nil {
		return fmt.Errorf("ipc unavailable: %w", err)
	}
	tokens, err := c.ListTokens(commandContext(cmd))
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(tokens)
	}
	// IDs are 32 characters and names run to 63, so the columns fit what they
	// hold.
	table := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "ID\tNAME\tSTATUS\tEXPIRES")
	now := time.Now()
	for _, tok := range tokens {
		status := "unused"
		switch {
		case !tok.UsedAt.IsZero():
			status = "used"
		case !now.Before(tok.ExpiresAt):
			status = "expired"
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\n",
			tok.TokenID, tok.Name, status, formatTime(tok.ExpiresAt, "2006-01-02 15:04"))
	}
	return table.Flush()
}

func runTokenRevoke(cmd *cobra.Command, args []string) error {
	c, err := ipc.NewClient(serverIPCSocket(cmd))
	if err != nil {
		return fmt.Errorf("ipc unavailable: %w", err)
	}
	if err := c.DeleteToken(commandContext(cmd), args[0]); err != nil {
		return err
	}
	fmt.Printf("token %q revoked\n", args[0])
	return nil
}

// ---------------------------------------------------------------------------
// TUI default
// ---------------------------------------------------------------------------

func runServerTUI(cmd *cobra.Command, _ []string) error {
	c, err := ipc.NewClient(serverIPCSocket(cmd))
	if err != nil {
		return fmt.Errorf("ipc unavailable: %w", err)
	}
	_, err = tea.NewProgram(tuiserver.New(c)).Run()
	return err
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

type serverReloader interface {
	ReloadServer(context.Context) error
}

var dialServerReloader = func(path string) (serverReloader, error) {
	return ipc.NewClient(path)
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func defaultServerCfgPath() string {
	if p := os.Getenv("SIGILS_CONFIG"); p != "" {
		return p
	}
	return internalsvc.DefaultServerConfigPath()
}
