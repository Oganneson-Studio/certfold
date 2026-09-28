package commands

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/Oganneson-Studio/sigil/internal/config"
	"github.com/Oganneson-Studio/sigil/internal/ipc"
)

type configChangeResult struct {
	Name                   string `json:"name"`
	ConfigPath             string `json:"config_path"`
	Reloaded               bool   `json:"reloaded"`
	RestartRequired        bool   `json:"restart_required"`
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
	renewDays, _ := cmd.Flags().GetInt("renew-days-before")
	subscribers, _ := cmd.Flags().GetStringSlice("subscribers")
	spec := config.CertificateSpec{
		Name:            strings.TrimSpace(args[0]),
		Domains:         cleanStringList(domains),
		CA:              strings.TrimSpace(caName),
		DNSProvider:     strings.TrimSpace(dnsProvider),
		KeyType:         strings.TrimSpace(keyType),
		RenewDaysBefore: renewDays,
		Subscribers:     cleanStringList(subscribers),
	}

	cfgPath := serverConfigPath(cmd)
	if _, err := config.AddCertificateSpec(cfgPath, spec); err != nil {
		return err
	}
	reloaded, err := reloadServerAfterConfigChange(cmd, cfgPath)
	if err != nil {
		return err
	}
	result := configChangeResult{
		Name:            spec.Name,
		ConfigPath:      cfgPath,
		Reloaded:        reloaded,
		RestartRequired: !reloaded,
	}
	if asJSON, _ := cmd.Root().PersistentFlags().GetBool("json"); asJSON {
		return printJSON(result)
	}
	fmt.Printf("certificate %q added to %s\n", spec.Name, cfgPath)
	if reloaded {
		fmt.Println("running sigils configuration reloaded")
	} else {
		fmt.Println("sigils is not running; the change will apply at the next startup")
	}
	return nil
}

func runCertRemove(cmd *cobra.Command, args []string) error {
	name := args[0]
	cfgPath := serverConfigPath(cmd)
	if err := config.RemoveCertificateSpec(cfgPath, name); err != nil {
		return err
	}
	reloaded, err := reloadServerAfterConfigChange(cmd, cfgPath)
	if err != nil {
		return err
	}
	result := configChangeResult{
		Name:                   name,
		ConfigPath:             cfgPath,
		Reloaded:               reloaded,
		RestartRequired:        !reloaded,
		StoredMaterialRetained: true,
	}
	if asJSON, _ := cmd.Root().PersistentFlags().GetBool("json"); asJSON {
		return printJSON(result)
	}
	fmt.Printf("certificate %q removed from %s\n", name, cfgPath)
	if reloaded {
		fmt.Println("running sigils configuration reloaded; stored certificate material remains in the database")
	} else {
		fmt.Println("sigils is not running; the change will apply at the next startup and stored certificate material remains in the database")
	}
	return nil
}

func reloadServerAfterConfigChange(cmd *cobra.Command, cfgPath string) (bool, error) {
	c, err := dialServerReloader(serverIPCSocket(cmd))
	if daemonNotRunning(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("configuration saved to %s, but the sigils daemon could not be notified: %w", cfgPath, err)
	}
	if err := c.ReloadServer(commandContext(cmd)); err != nil {
		return false, fmt.Errorf("configuration saved to %s, but the running sigils daemon rejected reload: %w", cfgPath, err)
	}
	return true, nil
}

// daemonNotRunning reports whether a dial error shows that no daemon listens
// on the endpoint: it does not exist, or nothing accepts connections on it.
// Any other error, such as a denied permission, may hide a running daemon.
func daemonNotRunning(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED)
}

func runCertRenew(cmd *cobra.Command, args []string) error {
	c, err := dialIPC(serverIPCSocket(cmd))
	if err != nil {
		return fmt.Errorf("ipc unavailable: %w", err)
	}
	if err := c.RenewCert(commandContext(cmd), args[0]); err != nil {
		return err
	}
	if asJSON, _ := cmd.Root().PersistentFlags().GetBool("json"); asJSON {
		return printJSON(renewalResult{Name: args[0], Renewed: true})
	}
	fmt.Printf("certificate %q renewed\n", args[0])
	return nil
}

func runClientShow(cmd *cobra.Command, args []string) error {
	c, err := dialIPC(serverIPCSocket(cmd))
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
			lastSeen = details.LastSeen.Format("2006-01-02 15:04:05 MST")
		}
		fmt.Printf("Name:        %s\n", details.Name)
		fmt.Printf("Fingerprint: %s\n", details.Fingerprint)
		fmt.Printf("Enrolled At: %s\n", details.EnrolledAt.Format("2006-01-02 15:04:05 MST"))
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

// formatTime formats value with layout, or returns "-" for the zero time.
func formatTime(value time.Time, layout string) string {
	if value.IsZero() {
		return "-"
	}
	return value.Format(layout)
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

func serverIPCSocket(cmd *cobra.Command) string {
	if path, _ := cmd.Root().PersistentFlags().GetString("ipc"); path != "" {
		return path
	}
	if _, socket, err := config.ReadServerPaths(serverConfigPath(cmd)); err == nil && socket != "" {
		return socket
	}
	return ipc.DefaultServerSocket()
}
