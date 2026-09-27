package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/Oganneson-Studio/sigil/internal/client"
	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/enroll"
	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/securefile"
	internalsvc "github.com/Oganneson-Studio/sigil/internal/service"
	tuiclient "github.com/Oganneson-Studio/sigil/internal/tui/client"
	"github.com/Oganneson-Studio/sigil/internal/version"
)

// ---------------------------------------------------------------------------
// serve (daemon loop)
// ---------------------------------------------------------------------------

func runServe(cmd *cobra.Command, _ []string) error {
	cfgPath, _ := cmd.Root().PersistentFlags().GetString("config")
	if cfgPath == "" {
		cfgPath = defaultClientCfgPath()
	}
	cfg, err := config.LoadClient(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	c, err := client.New(cfg, client.WithIdentitySaver(func(caCert, clientCert, clientKey string) error {
		return enroll.SaveIdentity(cfgPath, caCert, clientCert, clientKey)
	}))
	if err != nil {
		return fmt.Errorf("init client: %w", err)
	}

	// IPC server.
	ipcSocket := cfg.Client.IPCSocket
	if ipcSocket == "" {
		ipcSocket = ipc.DefaultClientSocket()
	}
	ipcListener, err := ipc.Listen(ipcSocket)
	if err != nil {
		return fmt.Errorf("ipc listen: %w", err)
	}
	control := &ipc.ClientControlDeps{
		State: func(context.Context) (ipc.ClientState, error) {
			status := c.Status()
			return ipc.ClientState{
				Name:       status.Name,
				ServerURL:  status.ServerURL,
				Online:     status.Online,
				LastPullAt: status.LastPullAt,
				LastError:  status.LastError,
				Certs:      status.Certs,
			}, nil
		},
		Fetch: c.Fetch,
		Reload: func(context.Context) error {
			updated, err := config.LoadClient(cfgPath)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			return c.Reload(updated)
		},
	}
	go func() { _ = ipc.Serve(ctx, ipcListener, ipc.ServerDeps{Client: control}) }()

	fmt.Printf("sigilc %s starting (server: %s)\n", version.Version, cfg.Client.ServerURL)
	return c.Run(ctx)
}

// ---------------------------------------------------------------------------
// reload
// ---------------------------------------------------------------------------

func runReload(cmd *cobra.Command, _ []string) error {
	ipcSocket := clientIPCSocket(cmd)
	c, err := ipc.NewClient(ipcSocket)
	if err != nil {
		return fmt.Errorf("ipc dial: %w", err)
	}
	if err := c.ReloadClient(context.Background()); err != nil {
		return err
	}
	fmt.Println("reload sent")
	return nil
}

// ---------------------------------------------------------------------------
// enroll
// ---------------------------------------------------------------------------

func runEnroll(cmd *cobra.Command, _ []string) error {
	tokenStr, _ := cmd.Flags().GetString("token")
	cfgPath, _ := cmd.Root().PersistentFlags().GetString("config")
	if cfgPath == "" {
		cfgPath = defaultClientCfgPath()
	}

	// Decode the opaque token to get the server URL.
	payload, err := enroll.DecodeToken(tokenStr)
	if err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}
	clientName, err := ensureEnrollmentConfig(cfgPath, payload.Name, payload.ServerURL)
	if err != nil {
		return err
	}

	kc, err := enroll.GenerateKeyAndCSR(clientName)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	resp, err := enroll.PostEnroll(payload.ServerURL, tokenStr, kc.CSRDER)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}

	if err := enroll.SaveIdentity(cfgPath, resp.CACert, resp.ClientCert, string(kc.KeyPEM)); err != nil {
		return fmt.Errorf("save identity: %w", err)
	}

	fmt.Printf("enrolled as %q — identity written to %s\n", clientName, cfgPath)
	return nil
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

func runStatus(cmd *cobra.Command, _ []string) error {
	asJSON, _ := cmd.Flags().GetBool("json")
	ipcSocket := clientIPCSocket(cmd)
	c, err := ipc.NewClient(ipcSocket)
	if err != nil {
		if asJSON {
			fmt.Println(`{"error":"daemon not running"}`)
		} else {
			fmt.Fprintln(os.Stderr, "sigilc daemon is not running")
		}
		return nil
	}
	st, err := c.GetClientState(context.Background())
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(st)
	}
	state := "offline"
	if st.Online {
		state = "online"
	}
	fmt.Printf("Client       : %s\n", st.Name)
	fmt.Printf("Server       : %s (%s)\n", st.ServerURL, state)
	fmt.Printf("Certificates : %d\n", len(st.Certs))
	if st.LastError != "" {
		fmt.Printf("Last error   : %s\n", st.LastError)
	}
	return nil
}

// ---------------------------------------------------------------------------
// fetch
// ---------------------------------------------------------------------------

func runFetch(cmd *cobra.Command, _ []string) error {
	ipcSocket := clientIPCSocket(cmd)
	c, err := ipc.NewClient(ipcSocket)
	if err != nil {
		return fmt.Errorf("ipc unavailable (is sigilc daemon running?): %w", err)
	}
	certName, _ := cmd.Flags().GetString("cert")
	if err := c.FetchClient(context.Background(), certName); err != nil {
		return err
	}
	fmt.Println("fetch triggered")
	return nil
}

// ---------------------------------------------------------------------------
// TUI default
// ---------------------------------------------------------------------------

func runDefaultTUI(cmd *cobra.Command, args []string) error {
	return runClientTUI(cmd, args)
}

func runClientTUI(cmd *cobra.Command, _ []string) error {
	ipcSocket := clientIPCSocket(cmd)
	ipcClient, _ := ipc.NewClient(ipcSocket)

	cfgPath, _ := cmd.Root().PersistentFlags().GetString("config")
	if cfgPath == "" {
		cfgPath = defaultClientCfgPath()
	}
	clientName := "sigilc"
	serverURL := ""
	if cfg, err := config.LoadClient(cfgPath); err == nil {
		clientName = cfg.Client.Name
		serverURL = cfg.Client.ServerURL
	}

	m := tuiclient.New(clientName, serverURL, ipcClient)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func defaultClientCfgPath() string {
	if p := os.Getenv("SIGILC_CONFIG"); p != "" {
		return p
	}
	return internalsvc.DefaultClientConfigPath()
}

func clientIPCSocket(cmd *cobra.Command) string {
	if path, _ := cmd.Root().PersistentFlags().GetString("ipc"); path != "" {
		return path
	}
	cfgPath, _ := cmd.Root().PersistentFlags().GetString("config")
	if cfgPath == "" {
		cfgPath = defaultClientCfgPath()
	}
	if cfg, err := config.LoadClient(cfgPath); err == nil && cfg.Client.IPCSocket != "" {
		return cfg.Client.IPCSocket
	}
	return ipc.DefaultClientSocket()
}

func ensureEnrollmentConfig(cfgPath, tokenName, serverURL string) (string, error) {
	cfg, err := config.LoadClient(cfgPath)
	if err == nil {
		if tokenName != "" && cfg.Client.Name != tokenName {
			return "", fmt.Errorf("client name %q does not match token name %q", cfg.Client.Name, tokenName)
		}
		if cfg.Client.ServerURL != serverURL {
			return "", fmt.Errorf("configured server URL %q does not match token server URL %q", cfg.Client.ServerURL, serverURL)
		}
		return cfg.Client.Name, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("load config: %w", err)
	}
	if tokenName == "" {
		return "", fmt.Errorf("token does not contain a client name")
	}

	initial := struct {
		Client config.ClientSection `yaml:"client"`
	}{
		Client: config.ClientSection{
			Name:      tokenName,
			ServerURL: serverURL,
			DataDir:   defaultClientDataDir(),
		},
	}
	raw, err := yaml.Marshal(initial)
	if err != nil {
		return "", fmt.Errorf("marshal initial config: %w", err)
	}
	if err := securefile.WriteFile(cfgPath, raw); err != nil {
		return "", fmt.Errorf("write initial config: %w", err)
	}
	return tokenName, nil
}

func defaultClientDataDir() string {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("PROGRAMDATA")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "Sigil", "data")
	case "darwin":
		return "/usr/local/var/sigilc"
	default:
		return "/var/lib/sigilc"
	}
}
