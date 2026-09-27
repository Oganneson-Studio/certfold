package commands

import (
	"fmt"
	"io/fs"
	"os"

	"github.com/spf13/cobra"

	"github.com/Oganneson-Studio/sigil/internal/config"
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
	withClients, _ := cmd.Flags().GetBool("with-clients")
	// Resolve data_dir before registering the service so a configuration
	// problem does not leave a half-finished installation.
	var dataDir string
	if withClients {
		var err error
		if dataDir, err = serviceDataDir(cfg); err != nil {
			return err
		}
	}

	if err := internalsvc.Install(internalsvc.NoopDaemon(), cfg); err != nil {
		return err
	}
	fmt.Println("sigils service installed successfully.")
	if !withClients {
		return nil
	}

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

// serviceDataDir returns server.data_dir from the configuration file the
// installed service is started with.
func serviceDataDir(cfg internalsvc.Config) (string, error) {
	path := cfg.ConfigPath
	if path == "" {
		path = internalsvc.DefaultServerConfigPath()
	}
	dataDir, _, err := config.ReadServerPaths(path)
	if err != nil {
		return "", fmt.Errorf("read server.data_dir to unpack sigilc binaries: %w", err)
	}
	if dataDir == "" {
		return "", fmt.Errorf("server.data_dir is not set in %s; it is needed to unpack sigilc binaries", path)
	}
	return dataDir, nil
}

// subFS returns an fs.FS rooted at dir inside fsys.
func subFS(fsys fs.FS, dir string) (fs.FS, error) {
	return fs.Sub(fsys, dir)
}
