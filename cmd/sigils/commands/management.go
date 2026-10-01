package commands

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/ipc"
)

type configChangeResult struct {
	Name                   string `json:"name"`
	ConfigPath             string `json:"config_path"`
	StoredMaterialRetained bool   `json:"stored_material_retained,omitempty"`
}

type renewalResult struct {
	Name    string `json:"name"`
	Renewed bool   `json:"renewed"`
}

type certificateDetails struct {
	Name          string     `json:"name"`
	CA            string     `json:"ca"`
	Domains       []string   `json:"domains"`
	Subscribers   []string   `json:"subscribers"`
	NotAfter      *time.Time `json:"not_after,omitempty"`
	RenewAt       *time.Time `json:"renew_at,omitempty"`
	RenewSource   string     `json:"renew_source,omitempty"`
	Fingerprint   string     `json:"fingerprint,omitempty"`
	IssuedAt      *time.Time `json:"issued_at,omitempty"`
	UpdatedAt     *time.Time `json:"updated_at,omitempty"`
	State         string     `json:"state"`
	Failures      int        `json:"failures"`
	LastError     string     `json:"last_error,omitempty"`
	LastAttemptAt *time.Time `json:"last_attempt_at,omitempty"`
	NextAttemptAt *time.Time `json:"next_attempt_at,omitempty"`
}

type clientDetails struct {
	Name        string     `json:"name"`
	Fingerprint string     `json:"fingerprint"`
	EnrolledAt  time.Time  `json:"enrolled_at"`
	LastSeen    *time.Time `json:"last_seen,omitempty"`
}

func runCertAdd(cmd *cobra.Command, args []string) error {
	domains, _ := cmd.Flags().GetStringSlice("domains")
	dnsProvider, _ := cmd.Flags().GetString("dns")
	if len(domains) == 0 {
		return fmt.Errorf("at least one --domains value is required")
	}
	if strings.TrimSpace(dnsProvider) == "" {
		return fmt.Errorf("--dns is required")
	}

	caName, _ := cmd.Flags().GetString("ca")
	keyType, _ := cmd.Flags().GetString("key-type")
	subscribers, _ := cmd.Flags().GetStringSlice("subscribers")
	req := ipc.AddCertificateRequest{
		Name:        strings.TrimSpace(args[0]),
		Domains:     cleanStringList(domains),
		CA:          strings.TrimSpace(caName),
		DNSProvider: strings.TrimSpace(dnsProvider),
		KeyType:     strings.TrimSpace(keyType),
		Subscribers: cleanStringList(subscribers),
	}

	// The running daemon edits the server.yaml it runs, checks the result
	// with its own environment, which holds what the ${VAR} references of
	// the file need, and applies it.
	c, err := dialServer(cmd)
	if err != nil {
		return fmt.Errorf("ipc unavailable: %w", err)
	}
	changed, err := c.AddCertificate(commandContext(cmd), req)
	if err != nil {
		return err
	}
	result := configChangeResult{Name: req.Name, ConfigPath: changed.ConfigPath}
	if asJSON, _ := cmd.Root().PersistentFlags().GetBool("json"); asJSON {
		return printJSON(result)
	}
	fmt.Printf("certificate %q added to %s\n", req.Name, changed.ConfigPath)
	fmt.Println("running sigils configuration reloaded")
	return nil
}

func runCertRemove(cmd *cobra.Command, args []string) error {
	name := args[0]
	// As for cert add, the running daemon edits and applies server.yaml.
	c, err := dialServer(cmd)
	if err != nil {
		return fmt.Errorf("ipc unavailable: %w", err)
	}
	changed, err := c.RemoveCertificate(commandContext(cmd), name)
	if err != nil {
		return err
	}
	result := configChangeResult{
		Name:                   name,
		ConfigPath:             changed.ConfigPath,
		StoredMaterialRetained: true,
	}
	if asJSON, _ := cmd.Root().PersistentFlags().GetBool("json"); asJSON {
		return printJSON(result)
	}
	fmt.Printf("certificate %q removed from %s\n", name, changed.ConfigPath)
	fmt.Println("running sigils configuration reloaded; stored certificate material remains in the database")
	return nil
}

func runCertRenew(cmd *cobra.Command, args []string) error {
	c, err := dialServer(cmd)
	if err != nil {
		return fmt.Errorf("ipc unavailable: %w", err)
	}
	// Ctrl-C ends the wait rather than the process, so that the error can
	// say what becomes of the renewal: once it runs, the daemon finishes it
	// and stores the certificate whether anyone waits or not.
	ctx, stop := signal.NotifyContext(commandContext(cmd), os.Interrupt)
	defer stop()
	if err := c.RenewCert(ctx, args[0]); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("%w; the renewal may still finish in the daemon: see `sigils events` or `sigils cert show %s`", err, args[0])
		}
		return err
	}
	if asJSON, _ := cmd.Root().PersistentFlags().GetBool("json"); asJSON {
		return printJSON(renewalResult{Name: args[0], Renewed: true})
	}
	fmt.Printf("certificate %q renewed\n", args[0])
	return nil
}

func runClientShow(cmd *cobra.Command, args []string) error {
	c, err := dialServer(cmd)
	if err != nil {
		return fmt.Errorf("ipc unavailable: %w", err)
	}
	clients, err := c.ListClients(commandContext(cmd))
	if err != nil {
		return err
	}
	for _, rec := range clients {
		if rec.Name != args[0] {
			continue
		}
		details := newClientDetails(rec)
		if asJSON, _ := cmd.Root().PersistentFlags().GetBool("json"); asJSON {
			return printJSON(details)
		}
		lastSeen := "never"
		if details.LastSeen != nil {
			lastSeen = formatTime(*details.LastSeen, timeLayout)
		}
		fmt.Printf("Name:        %s\n", details.Name)
		fmt.Printf("Fingerprint: %s\n", details.Fingerprint)
		fmt.Printf("Enrolled At: %s\n", formatTime(details.EnrolledAt, timeLayout))
		fmt.Printf("Last Seen:   %s\n", lastSeen)
		return nil
	}
	return fmt.Errorf("client %q not found", args[0])
}

func newClientDetails(rec *ipc.ClientInfo) clientDetails {
	var lastSeen *time.Time
	if !rec.LastSeen.IsZero() {
		value := rec.LastSeen
		lastSeen = &value
	}
	return clientDetails{
		Name:        rec.Name,
		Fingerprint: rec.Fingerprint,
		EnrolledAt:  rec.EnrolledAt,
		LastSeen:    lastSeen,
	}
}

func newCertificateDetails(rec *ipc.CertificateInfo) certificateDetails {
	return certificateDetails{
		Name:          rec.Name,
		CA:            rec.CA,
		Domains:       append([]string(nil), rec.Domains...),
		Subscribers:   append([]string{}, rec.Subscribers...), // [] rather than null for none
		NotAfter:      timePointer(rec.NotAfter),
		RenewAt:       timePointer(rec.RenewAt),
		RenewSource:   rec.RenewSource,
		Fingerprint:   rec.Fingerprint,
		IssuedAt:      timePointer(rec.IssuedAt),
		UpdatedAt:     timePointer(rec.UpdatedAt),
		State:         rec.State,
		Failures:      rec.Failures,
		LastError:     rec.LastError,
		LastAttemptAt: timePointer(rec.LastAttemptAt),
		NextAttemptAt: timePointer(rec.NextAttemptAt),
	}
}

func certificateDetailList(records []*ipc.CertificateInfo) []certificateDetails {
	out := make([]certificateDetails, 0, len(records))
	for _, rec := range records {
		out = append(out, newCertificateDetails(rec))
	}
	return out
}

func clientDetailList(records []*ipc.ClientInfo) []clientDetails {
	out := make([]clientDetails, 0, len(records))
	for _, rec := range records {
		out = append(out, newClientDetails(rec))
	}
	return out
}

func timePointer(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	copy := value
	return &copy
}

// timeLayout is the layout of a time of day that people read: in local
// time, with the offset from UTC as a number, which Windows has for every
// zone, rather than the zone's abbreviation, which it lacks.
const timeLayout = "2006-01-02 15:04:05 -07:00"

// formatTime formats value in local time with layout, or returns "-" for the
// zero time.
func formatTime(value time.Time, layout string) string {
	if value.IsZero() {
		return "-"
	}
	return value.Local().Format(layout)
}

// formatRenewAt formats when cert is due for renewal with layout, followed by
// the source of that time, "(ari)" or "(ratio)"; without stored material it
// returns "-".
func formatRenewAt(cert *ipc.CertificateInfo, layout string) string {
	at := formatTime(cert.RenewAt, layout)
	if cert.RenewSource != "" {
		at += " (" + cert.RenewSource + ")"
	}
	return at
}

func cleanStringList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func commandContext(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}

func serverConfigPath(cmd *cobra.Command) string {
	path, _ := cmd.Root().PersistentFlags().GetString("config")
	if path == "" {
		path = defaultServerCfgPath()
	}
	return path
}

// serverIPCSocket returns the IPC endpoint of the daemon: --ipc, else
// server.ipc_socket, else the platform default. A server.yaml this user may
// not read counts as none: such a user may not open the endpoint of the
// daemon either, which the error of the default one says, and sigils service
// status reports as a daemon it cannot check. An ipc_socket that cannot be
// read is an error, not the default, where another daemon may answer.
func serverIPCSocket(cmd *cobra.Command) (string, error) {
	if path, _ := cmd.Root().PersistentFlags().GetString("ipc"); path != "" {
		return path, nil
	}
	cfgPath := serverConfigPath(cmd)
	socket, err := config.ReadServerField(cfgPath, "ipc_socket")
	switch {
	case errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission):
		return ipc.DefaultServerSocket(), nil
	case err != nil:
		return "", fmt.Errorf("read the IPC endpoint from %s: %w (pass --ipc to give it instead)", cfgPath, err)
	case socket == "":
		return ipc.DefaultServerSocket(), nil
	}
	return socket, nil
}

// dialServer connects to the daemon at the endpoint serverIPCSocket resolves.
func dialServer(cmd *cobra.Command) (*ipc.Client, error) {
	socket, err := serverIPCSocket(cmd)
	if err != nil {
		return nil, err
	}
	return ipc.NewClient(socket)
}
