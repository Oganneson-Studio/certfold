package commands

import (
	"fmt"
	"io/fs"
	"os"

	"github.com/spf13/cobra"

	"github.com/Oganneson-Studio/certfold/internal/config"
	internalsvc "github.com/Oganneson-Studio/certfold/internal/service"
)

func newServiceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: "Manage the certfolds system service",
	}

	install := &cobra.Command{
		Use:   "install",
		Short: "Register certfolds as a system service (systemd / Windows Service / launchd)",
		RunE:  runServerServiceInstall,
	}
	install.Flags().Bool("with-clients", false, "unpack bundled certfoldc binaries into data_dir/binaries/")

	cmd.AddCommand(
		install,
		&cobra.Command{Use: "uninstall", Short: "Remove the system service", RunE: runServerServiceControl("uninstall")},
		&cobra.Command{Use: "start", Short: "Start the system service", RunE: runServerServiceControl("start")},
		&cobra.Command{Use: "stop", Short: "Stop the system service", RunE: runServerServiceControl("stop")},
		&cobra.Command{Use: "restart", Short: "Restart the system service", RunE: runServerServiceControl("restart")},
		&cobra.Command{Use: "status", Short: "Show system service status", RunE: runServerServiceStatus},
	)
	for _, sub := range cmd.Commands() {
		withoutJSON(sub)
	}
	return cmd
}

// serverSvcConfig returns the service of certfolds started with the
// configuration file the other commands read.
func serverSvcConfig(cmd *cobra.Command) internalsvc.Config {
	return internalsvc.Config{
		Role:       internalsvc.RoleServer,
		ConfigPath: serverConfigPath(cmd),
	}
}

func runServerServiceInstall(cmd *cobra.Command, _ []string) error {
	cfg := serverSvcConfig(cmd)
	// The binaries are unpacked before the service is registered, so a
	// problem with either does not leave a half-finished installation.
	if withClients, _ := cmd.Flags().GetBool("with-clients"); withClients {
		dataDir, err := serviceDataDir(cfg)
		if err != nil {
			return err
		}
		sub, err := fs.Sub(internalsvc.ClientBinariesFS(), "dist")
		if err != nil {
			return fmt.Errorf("client binaries embed: %w", err)
		}
		n, err := internalsvc.UnpackClients(sub, dataDir, os.Stdout)
		if err != nil {
			return err
		}
		if n > 0 {
			fmt.Printf("%d certfoldc binary/ies unpacked to %s/binaries/\n", n, dataDir)
		}
	}

	if err := internalsvc.Install(internalsvc.NoopDaemon(), cfg); err != nil {
		return err
	}
	fmt.Println("certfolds service installed successfully.")
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
	socket, err := serverIPCSocket(cmd)
	if err != nil {
		return err
	}
	status, err := internalsvc.StatusText(internalsvc.NoopDaemon(), cfg, socket)
	if err != nil {
		return err
	}
	fmt.Println(status)
	return nil
}

// serviceDataDir returns server.data_dir from the configuration file the
// installed service is started with.
func serviceDataDir(cfg internalsvc.Config) (string, error) {
	dataDir, err := config.ReadServerField(cfg.ConfigPath, "data_dir")
	if err != nil {
		return "", fmt.Errorf("read server.data_dir to unpack certfoldc binaries: %w", err)
	}
	if dataDir == "" {
		return "", fmt.Errorf("server.data_dir is not set in %s; it is needed to unpack certfoldc binaries", cfg.ConfigPath)
	}
	return dataDir, nil
}
