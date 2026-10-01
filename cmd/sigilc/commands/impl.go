package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/Oganneson-Studio/sigil/internal/agent"
	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/enroll"
	"github.com/Oganneson-Studio/sigil/internal/ipc"
	"github.com/Oganneson-Studio/sigil/internal/logging"
	"github.com/Oganneson-Studio/sigil/internal/securefile"
	internalsvc "github.com/Oganneson-Studio/sigil/internal/service"
	tuiclient "github.com/Oganneson-Studio/sigil/internal/tui/client"
	"github.com/Oganneson-Studio/sigil/internal/tui/shared"
)

// ---------------------------------------------------------------------------
// serve (daemon loop)
// ---------------------------------------------------------------------------

func runServe(cmd *cobra.Command, _ []string) error {
	cfgPath := clientConfigPath(cmd)
	return internalsvc.Run(clientSvcConfig(cmd), func(ctx context.Context, logs logging.Logs) error {
		return agent.Run(ctx, cfgPath, logs)
	})
}

// ---------------------------------------------------------------------------
// reload
// ---------------------------------------------------------------------------

func runReload(cmd *cobra.Command, _ []string) error {
	c, err := dialDaemon(cmd)
	if err != nil {
		return err
	}
	if err := c.ReloadClient(context.Background()); err != nil {
		return err
	}
	fmt.Println("configuration applied and outputs reconciled; see sigilc status for errors")
	return nil
}

// ---------------------------------------------------------------------------
// enroll
// ---------------------------------------------------------------------------

func runEnroll(cmd *cobra.Command, _ []string) (err error) {
	tokenStr, _ := cmd.Flags().GetString("token")
	if tokenStr == "" {
		// Any user may read the command line of a process, but not its
		// environment: the install scripts hand the token over this way.
		tokenStr = os.Getenv("SIGILC_TOKEN")
	}
	if tokenStr == "" {
		return errors.New("no enrollment token: set SIGILC_TOKEN, or pass --token")
	}
	cfgPath := clientConfigPath(cmd)

	// Decode the opaque token to get the server URL.
	payload, err := enroll.DecodeToken(tokenStr)
	if err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}
	clientName, created, err := ensureEnrollmentConfig(cfgPath, payload.Name, payload.ServerURL)
	if err != nil {
		return err
	}
	if created {
		// Until the identity is saved, a failure removes the client.yaml
		// this enrollment wrote: without an identity it would only bind the
		// next enrollment to the client name and server URL of this token.
		defer func() {
			if err != nil {
				_ = os.Remove(cfgPath)
			}
		}()
	}

	kc, err := enroll.GenerateKeyAndCSR(clientName)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	clientCert, err := enroll.PostEnroll(payload, tokenStr, kc.CSRDER)
	if err != nil {
		// The error can quote the network, such as the DNS names in the
		// certificate of a man in the middle: a newline there must not start
		// a line under the one main prints, which keeps newlines.
		msg := "enroll: " + logging.OneLine(err.Error())
		if errors.Is(err, enroll.ErrUnusableAnswer) {
			return fmt.Errorf("%s; %s", msg, tokenTaken(clientName))
		}
		return errors.New(msg)
	}

	if err := enroll.SaveIdentity(cfgPath, payload.CACert, clientCert, string(kc.KeyPEM)); err != nil {
		return fmt.Errorf("save identity: %w; %s", err, tokenTaken(clientName))
	}

	fmt.Printf("enrolled as %q — identity written to %s\n", clientName, cfgPath)
	if !created {
		// The server now accepts only the new identity, and a daemon that
		// runs goes on with the one it loaded until it reads client.yaml
		// again. The line is printed only when a daemon answers on its
		// endpoint: the install scripts stop the service before they enroll.
		// The dial takes at most the two seconds for which a busy Windows
		// pipe is retried, and any error counts as no daemon.
		if _, err := dialDaemon(cmd); err == nil {
			fmt.Println("a running sigilc daemon keeps its old identity, which the server no longer accepts, " +
				"until `sigilc reload` or a restart of the sigilc service")
		}
	}
	return nil
}

// tokenTaken says what an enrollment of name that failed once the server had
// taken the token means: the server now accepts only the identity it issued,
// which sigilc has not saved, and enrolling again needs a new token. The
// name may have had no identity before.
func tokenTaken(name string) string {
	return fmt.Sprintf("the server took the token, so any earlier identity of %q no longer works: "+
		"once this is fixed, create a token with `sigils token create --name %s --replace` and enroll again", name, name)
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

func runStatus(cmd *cobra.Command, _ []string) error {
	asJSON, _ := cmd.Flags().GetBool("json")
	st, err := clientState(cmd)
	if err != nil {
		if asJSON {
			_ = printJSON(struct {
				Error string `json:"error"`
			}{err.Error()})
		}
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

// statusTimeout bounds the state request of sigilc status, as it bounds each
// IPC call of a refresh of the TUI. A daemon that accepts the connection but
// never answers would otherwise hold it for the 5 minutes of the IPC client,
// and install.sh, which runs it until the daemon answers, for over an hour.
const statusTimeout = 10 * time.Second

// clientState asks the daemon for its state.
func clientState(cmd *cobra.Command) (*ipc.ClientState, error) {
	c, err := dialDaemon(cmd)
	if err != nil {
		return nil, err
	}
	return shared.Within(statusTimeout, c.GetClientState)
}

// ---------------------------------------------------------------------------
// fetch
// ---------------------------------------------------------------------------

func runFetch(cmd *cobra.Command, _ []string) error {
	c, err := dialDaemon(cmd)
	if err != nil {
		return err
	}
	certName, _ := cmd.Flags().GetString("cert")
	if err := c.FetchClient(context.Background(), certName); err != nil {
		return err
	}
	fmt.Println("pulled from sigils; outputs reconciled")
	return nil
}

// ---------------------------------------------------------------------------
// TUI default
// ---------------------------------------------------------------------------

func runClientTUI(cmd *cobra.Command, _ []string) error {
	ipcClient, err := dialDaemon(cmd)
	if err != nil {
		return err
	}
	p := tea.NewProgram(tuiclient.New(ipcClient))
	_, err = p.Run()
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

// dialDaemon connects to the daemon at the endpoint clientIPCSocket resolves.
// Its error says that the daemon is not running only when nothing listens
// there: a denied permission, or a pipe that another owner holds, may hide a
// daemon that runs.
func dialDaemon(cmd *cobra.Command) (*ipc.Client, error) {
	socket, err := clientIPCSocket(cmd)
	if err != nil {
		return nil, err
	}
	c, err := ipc.NewClient(socket)
	if daemonNotRunning(err) {
		return nil, fmt.Errorf("sigilc daemon is not running: %w", err)
	}
	return c, err
}

// daemonNotRunning reports whether a dial error shows that no daemon listens
// on the endpoint: it does not exist, or nothing accepts connections on it.
func daemonNotRunning(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED)
}

// clientConfigPath returns the path of client.yaml: --config, else
// $SIGILC_CONFIG, else the platform default.
func clientConfigPath(cmd *cobra.Command) string {
	path, _ := cmd.Root().PersistentFlags().GetString("config")
	if path == "" {
		path = defaultClientCfgPath()
	}
	return path
}

// clientIPCSocket returns the IPC endpoint of the daemon: --ipc, else
// client.ipc_socket, else the platform default. A client.yaml this user may
// not read counts as none: such a user may not open the endpoint of the
// daemon either, which the error of the default one says, and sigilc
// service status reports as a daemon it cannot check. An ipc_socket that
// cannot be read is an error, not the default, where another daemon may
// answer.
func clientIPCSocket(cmd *cobra.Command) (string, error) {
	if path, _ := cmd.Root().PersistentFlags().GetString("ipc"); path != "" {
		return path, nil
	}
	// Locating the daemon must not require the variables client.yaml takes
	// from the service's environment, other than those of ipc_socket.
	cfgPath := clientConfigPath(cmd)
	socket, err := config.ReadClientField(cfgPath, "ipc_socket")
	switch {
	case errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission):
		return ipc.DefaultClientSocket(), nil
	case err != nil:
		return "", fmt.Errorf("read the IPC endpoint from %s: %w (pass --ipc to give it instead)", cfgPath, err)
	case socket == "":
		return ipc.DefaultClientSocket(), nil
	}
	return socket, nil
}

// ensureEnrollmentConfig returns the name to enroll as. A client.yaml at
// cfgPath must name the client and server URL of the token; without one, it
// writes one that does, and reports that it created it. Writing it before
// the token is sent stops an enrollment that could not save its identity
// before the server spends the token. The client.yaml of an earlier install
// may take values from variables that only the service's environment sets,
// which a reinstall under sudo does not have: only the name and server URL
// are read.
func ensureEnrollmentConfig(cfgPath, tokenName, serverURL string) (name string, created bool, err error) {
	// An account sigilc does not trust that may write to the directory could
	// have put a client.yaml there that names this host and runs its own
	// on_change program.
	if err := securefile.CheckDirectory(filepath.Dir(cfgPath)); err != nil {
		return "", false, fmt.Errorf("configuration directory: %w", err)
	}
	name, err = config.ReadClientField(cfgPath, "name")
	if err == nil {
		if name != tokenName {
			return "", false, fmt.Errorf("client name %q in %s does not match token name %q; to enroll as %q, remove %s and try again",
				name, cfgPath, tokenName, tokenName, cfgPath)
		}
		url, err := config.ReadClientField(cfgPath, "server_url")
		if err != nil {
			return "", false, fmt.Errorf("load config: %w", err)
		}
		if url != serverURL {
			return "", false, fmt.Errorf("server URL %q in %s does not match token server URL %q; to enroll with %s, remove %s and try again",
				url, cfgPath, serverURL, serverURL, cfgPath)
		}
		return name, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", false, fmt.Errorf("load config: %w", err)
	}

	initial := struct {
		Client config.ClientSection `yaml:"client"`
	}{
		Client: config.ClientSection{
			Name:      tokenName,
			ServerURL: serverURL,
			DataDir:   config.DefaultClientDataDir(),
		},
	}
	raw, err := yaml.Marshal(initial)
	if err != nil {
		return "", false, fmt.Errorf("marshal initial config: %w", err)
	}
	if err := securefile.WriteFile(cfgPath, raw); err != nil {
		return "", false, fmt.Errorf("write initial config: %w", err)
	}
	return tokenName, true, nil
}
