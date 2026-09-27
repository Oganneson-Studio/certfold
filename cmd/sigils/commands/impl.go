package commands

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/Oganneson-Studio/sigil/internal/acme"
	"github.com/Oganneson-Studio/sigil/internal/api"
	"github.com/Oganneson-Studio/sigil/internal/ca"
	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/enroll"
	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/scheduler"
	internalsvc "github.com/Oganneson-Studio/sigil/internal/service"
	"github.com/Oganneson-Studio/sigil/internal/store"
	tuiserver "github.com/Oganneson-Studio/sigil/internal/tui/server"
)

// ---------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------

func runServe(cmd *cobra.Command, _ []string) error {
	cfgPath, _ := cmd.Root().PersistentFlags().GetString("config")
	if cfgPath == "" {
		cfgPath = defaultServerCfgPath()
	}
	cfg, err := config.LoadServer(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	db, err := store.Open(dbPath(cfg))
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer db.Close()

	miniCA, err := ca.Bootstrap(cfg.Server.DataDir)
	if err != nil {
		return fmt.Errorf("init CA: %w", err)
	}

	issuer := acme.NewIssuer(db.Accounts)

	enrollSvc := enroll.NewServer(db.Tokens, db.Clients, miniCA)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Issue (or re-use) a TLS server certificate signed by the mini-CA.
	serverTLSCert, err := serverTLSCertificate(miniCA, cfg)
	if err != nil {
		return fmt.Errorf("server TLS cert: %w", err)
	}

	// Renewal scheduler.
	pushNotifier := scheduler.NewHTTPPushNotifier(nil)
	r := scheduler.New(issuer, db.Certs, pushNotifier, nil)
	runtimeConfig := newServerConfigRuntime(cfgPath, cfg, r)
	go func() { _ = r.RunDynamic(ctx, runtimeConfig.Current) }()
	certificateControl := &ipc.CertificateControlDeps{
		Renew: func(ctx context.Context, name string) error {
			return r.RenewNamed(ctx, runtimeConfig.Current, name)
		},
	}
	serverControl := &ipc.ServerControlDeps{Reload: runtimeConfig.Reload}

	deps := api.Deps{
		ServerCfg:     cfg,
		CurrentServer: runtimeConfig.Current,
		DB:            db,
		MiniCA:        miniCA,
		DataDir:       cfg.Server.DataDir,
		EnrollServer:  enrollSvc,
	}

	// IPC server.
	ipcSocket := cfg.Server.IPCSocket
	ipcListener, err := ipc.Listen(ipcSocket)
	if err != nil {
		return fmt.Errorf("ipc listen: %w", err)
	}
	go func() {
		_ = ipc.Serve(ctx, ipcListener, ipc.ServerDeps{
			DB:           db,
			Server:       serverControl,
			Certificates: certificateControl,
		})
	}()

	// HTTPS server with mini-CA-signed server cert.
	httpSrv := api.New(deps, serverTLSCert)
	go func() {
		<-ctx.Done()
		_ = httpSrv.Close()
	}()
	fmt.Printf("sigils listening on %s (TLS)\n", cfg.Server.Listen)
	if err := httpSrv.ListenAndServeTLS("", ""); err != nil && err.Error() != "http: Server closed" {
		return err
	}
	return nil
}

// serverTLSCertificate builds the hosts list from the config and issues a
// server TLS cert signed by the mini-CA.
func serverTLSCertificate(miniCA *ca.MiniCA, cfg *config.ServerConfig) (tls.Certificate, error) {
	if cfg.Server.TLSCertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("load configured TLS certificate: %w", err)
		}
		return cert, nil
	}

	hosts := []string{"localhost", "127.0.0.1", "::1"}

	// Extract hostname from public_url if set.
	if cfg.Server.PublicURL != "" {
		if u, err := url.Parse(cfg.Server.PublicURL); err == nil && u.Hostname() != "" {
			hosts = append(hosts, u.Hostname())
		}
	}

	// Extract hostname from listen address if it has one (e.g. "sigil.internal:8443").
	if h, _, err := net.SplitHostPort(cfg.Server.Listen); err == nil && h != "" {
		hosts = append(hosts, h)
	}

	certPEM, keyPEM, err := miniCA.IssueServerCert(hosts)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// ---------------------------------------------------------------------------
// reload
// ---------------------------------------------------------------------------

type serverReloadResult struct {
	Reloaded bool `json:"reloaded"`
}

func runReload(cmd *cobra.Command, _ []string) error {
	if cmd == nil {
		return fmt.Errorf("command context unavailable")
	}
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
	if err == nil {
		return c, nil
	}
	if !cmd.Root().PersistentFlags().Changed("ipc") && path != ipc.DefaultServerSocket() {
		if fallback, fallbackErr := dialServerReloader(ipc.DefaultServerSocket()); fallbackErr == nil {
			return fallback, nil
		}
	}
	return nil, fmt.Errorf(
		"connect to %q: %w; if server.ipc_socket changed on disk, retry with --ipc set to the running daemon's current socket",
		path, err,
	)
}

// ---------------------------------------------------------------------------
// config validate / config show
// ---------------------------------------------------------------------------

func runConfigValidate(cmd *cobra.Command, _ []string) error {
	cfgPath, _ := cmd.Root().PersistentFlags().GetString("config")
	if cfgPath == "" {
		cfgPath = defaultServerCfgPath()
	}
	_, err := config.LoadServer(cfgPath)
	if err != nil {
		return err
	}
	fmt.Println("ok")
	return nil
}

func runConfigShow(cmd *cobra.Command, _ []string) error {
	cfgPath, _ := cmd.Root().PersistentFlags().GetString("config")
	if cfgPath == "" {
		cfgPath = defaultServerCfgPath()
	}
	cfg, err := config.LoadServer(cfgPath)
	if err != nil {
		return err
	}
	out, _ := yaml.Marshal(cfg)
	fmt.Print(string(out))
	return nil
}

// ---------------------------------------------------------------------------
// cert list / show
// ---------------------------------------------------------------------------

func runCertList(cmd *cobra.Command, _ []string) error {
	asJSON, _ := cmd.Root().PersistentFlags().GetBool("json")
	c, err := dialIPC(serverIPCSocket(cmd))
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
	fmt.Printf("%-20s %-12s %-30s %s\n", "NAME", "CA", "DOMAINS", "NOT AFTER")
	for _, cert := range certs {
		fmt.Printf("%-20s %-12s %-30s %s\n",
			cert.Name, cert.CA, strings.Join(cert.Domains, ","),
			cert.NotAfter.Format("2006-01-02"))
	}
	return nil
}

func runCertShow(cmd *cobra.Command, args []string) error {
	asJSON, _ := cmd.Root().PersistentFlags().GetBool("json")
	c, err := dialIPC(serverIPCSocket(cmd))
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
			fmt.Printf("Name:      %s\nCA:        %s\nDomains:   %s\nNot After: %s\n",
				cert.Name, cert.CA, strings.Join(cert.Domains, ", "),
				cert.NotAfter.Format("2006-01-02"))
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
	c, err := dialIPC(serverIPCSocket(cmd))
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
	fmt.Printf("%-20s %-30s %s\n", "NAME", "FINGERPRINT", "LAST SEEN")
	for _, cl := range clients {
		lastSeen := "never"
		if !cl.LastSeen.IsZero() {
			lastSeen = cl.LastSeen.Format("2006-01-02 15:04")
		}
		fmt.Printf("%-20s %-30s %s\n", cl.Name, cl.Fingerprint, lastSeen)
	}
	return nil
}

func runClientRemove(cmd *cobra.Command, args []string) error {
	c, err := dialIPC(serverIPCSocket(cmd))
	if err != nil {
		return fmt.Errorf("ipc unavailable: %w", err)
	}
	if err := c.DeleteClient(commandContext(cmd), args[0]); err != nil {
		return err
	}
	fmt.Printf("client %q removed\n", args[0])
	return nil
}

// ---------------------------------------------------------------------------
// token create / list / revoke
// ---------------------------------------------------------------------------

func runTokenCreate(cmd *cobra.Command, _ []string) error {
	name, _ := cmd.Flags().GetString("name")
	ttl, _ := cmd.Flags().GetDuration("expires")
	if ttl == 0 {
		ttl = time.Hour
	}

	cfgPath, _ := cmd.Root().PersistentFlags().GetString("config")
	if cfgPath == "" {
		cfgPath = defaultServerCfgPath()
	}
	cfg, err := config.LoadServer(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	db, err := store.Open(dbPath(cfg))
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer db.Close()

	miniCA, err := ca.Bootstrap(cfg.Server.DataDir)
	if err != nil {
		return fmt.Errorf("init CA: %w", err)
	}

	publicURL := cfg.PublicBaseURL()
	// Warn when public_url is not set: the fallback URL may lack a hostname and
	// will not be reachable by clients.
	if cfg.Server.PublicURL == "" {
		if h, _, err := net.SplitHostPort(cfg.Server.Listen); err == nil && h == "" {
			fmt.Fprintf(os.Stderr, "warning: server.public_url is not set; install URL may be unreachable (%s). Set server.public_url in server.yaml.\n", publicURL)
		}
	}
	srv := enroll.NewServer(db.Tokens, db.Clients, miniCA)
	tokenStr, err := srv.Create(context.Background(), publicURL, name, ttl)
	if err != nil {
		return fmt.Errorf("create token: %w", err)
	}

	fmt.Printf("Token: %s\n\n", tokenStr)
	fmt.Println("Install (Linux/macOS):")
	fmt.Printf("  curl -fsSL %s/install.sh | sudo sh -s -- --token %s\n\n", publicURL, tokenStr)
	fmt.Println("Install (Windows):")
	fmt.Printf("  iwr -useb '%s/install.ps1?token=%s' | iex\n", publicURL, tokenStr)
	return nil
}

func runTokenList(cmd *cobra.Command, _ []string) error {
	asJSON, _ := cmd.Root().PersistentFlags().GetBool("json")
	c, err := dialIPC(serverIPCSocket(cmd))
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
	fmt.Printf("%-20s %-20s %-10s %s\n", "ID", "NAME", "STATUS", "EXPIRES")
	for _, tok := range tokens {
		status := "unused"
		if !tok.UsedAt.IsZero() {
			status = "used"
		}
		fmt.Printf("%-20s %-20s %-10s %s\n",
			tok.TokenID, tok.Name, status, tok.ExpiresAt.Format("2006-01-02 15:04"))
	}
	return nil
}

func runTokenRevoke(cmd *cobra.Command, args []string) error {
	c, err := dialIPC(serverIPCSocket(cmd))
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
	ipcClient, _ := dialIPC(serverIPCSocket(cmd))
	m := tuiserver.New(ipcClient)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func dialIPC(path string) (*ipc.Client, error) {
	return ipc.NewClient(path)
}

type serverReloader interface {
	ReloadServer(context.Context) error
}

var dialServerReloader = func(path string) (serverReloader, error) {
	return dialIPC(path)
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func dbPath(cfg *config.ServerConfig) string {
	return filepath.Join(cfg.Server.DataDir, "sigils.db")
}

func defaultServerCfgPath() string {
	if p := os.Getenv("SIGILS_CONFIG"); p != "" {
		return p
	}
	return internalsvc.DefaultServerConfigPath()
}
