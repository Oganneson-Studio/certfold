package commands

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	internalsvc "github.com/Oganneson-Studio/sigil/internal/service"
)

func newServiceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: "Manage the sigils system service",
	}

	install := &cobra.Command{
		Use:   "install",
		Short: "Register sigils as a system service (systemd / Windows Service / launchd)",
		RunE:  runServerServiceInstall,
	}
	install.Flags().Bool("with-clients", false, "unpack bundled sigilc binaries into data_dir/binaries/")

	cmd.AddCommand(
		install,
		&cobra.Command{Use: "uninstall", Short: "Remove the system service", RunE: runServerServiceControl("uninstall")},
		&cobra.Command{Use: "start", Short: "Start the system service", RunE: runServerServiceControl("start")},
		&cobra.Command{Use: "stop", Short: "Stop the system service", RunE: runServerServiceControl("stop")},
		&cobra.Command{Use: "restart", Short: "Restart the system service", RunE: runServerServiceControl("restart")},
		&cobra.Command{Use: "status", Short: "Show system service status", RunE: runServerServiceStatus},
	)
	return cmd
}

func serverSvcConfig(cmd *cobra.Command) internalsvc.Config {
	cfgPath, _ := cmd.Root().PersistentFlags().GetString("config")
	return internalsvc.Config{
		Role:       internalsvc.RoleServer,
		ConfigPath: cfgPath,
	}
}

func runServerServiceInstall(cmd *cobra.Command, _ []string) error {
	cfg := serverSvcConfig(cmd)
	if err := internalsvc.Install(internalsvc.NoopDaemon(), cfg); err != nil {
		return err
	}
	fmt.Println("sigils service installed successfully.")

	withClients, _ := cmd.Flags().GetBool("with-clients")
	if !withClients {
		return nil
	}

	// Determine data_dir from server.yaml if possible; fall back to a default.
	dataDir := serverDataDir(cmd)
	fsys := internalsvc.ClientBinariesFS()
	sub, err := subFS(fsys, "dist")
	if err != nil {
		return fmt.Errorf("client binaries embed: %w", err)
	}
	n, err := internalsvc.UnpackClients(sub, dataDir, os.Stdout)
	if err != nil {
		return err
	}
	if n > 0 {
		fmt.Printf("%d sigilc binary/ies unpacked to %s/binaries/\n", n, dataDir)
	}
	return nil
}

func runServerServiceControl(action string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, _ []string) error {
		cfg := serverSvcConfig(cmd)
		d := internalsvc.NoopDaemon()
		switch action {
		case "uninstall":
			return internalsvc.Uninstall(d, cfg)
		case "start":
			return internalsvc.Start(d, cfg)
		case "stop":
			return internalsvc.Stop(d, cfg)
		case "restart":
			return internalsvc.Restart(d, cfg)
		default:
			return fmt.Errorf("unknown action %q", action)
		}
	}
}

func runServerServiceStatus(cmd *cobra.Command, _ []string) error {
	cfg := serverSvcConfig(cmd)
	status, err := internalsvc.StatusText(internalsvc.NoopDaemon(), cfg)
	if err != nil {
		return err
	}
	fmt.Println(status)
	return nil
}

// serverDataDir returns the server's data_dir. It tries to load server.yaml
// for the configured value; if unavailable it returns the platform default.
func serverDataDir(cmd *cobra.Command) string {
	cfgPath, _ := cmd.Root().PersistentFlags().GetString("config")
	return defaultDataDir(cfgPath)
}

// defaultDataDir returns the platform default data directory for sigils.
func defaultDataDir(_ string) string {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("PROGRAMDATA")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "Sigil", "data")
	case "darwin":
		return "/usr/local/var/sigils"
	default:
		return "/var/lib/sigils"
	}
}

// subFS returns an fs.FS rooted at dir inside fsys.
func subFS(fsys fs.FS, dir string) (fs.FS, error) {
	return fs.Sub(fsys, dir)
}
