package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	internalsvc "github.com/Oganneson-Studio/sigil/internal/service"
)

func newServiceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: "Manage the sigilc system service",
	}
	cmd.AddCommand(
		&cobra.Command{Use: "install", Short: "Register sigilc as a system service", RunE: runClientServiceControl("install")},
		&cobra.Command{Use: "uninstall", Short: "Remove the system service", RunE: runClientServiceControl("uninstall")},
		&cobra.Command{Use: "start", Short: "Start the system service", RunE: runClientServiceControl("start")},
		&cobra.Command{Use: "stop", Short: "Stop the system service", RunE: runClientServiceControl("stop")},
		&cobra.Command{Use: "restart", Short: "Restart the system service", RunE: runClientServiceControl("restart")},
		&cobra.Command{Use: "status", Short: "Show system service status", RunE: runClientServiceStatus},
	)
	return cmd
}

// clientSvcConfig returns the service of sigilc started with the
// configuration file the other commands read.
func clientSvcConfig(cmd *cobra.Command) internalsvc.Config {
	return internalsvc.Config{
		Role:       internalsvc.RoleClient,
		ConfigPath: clientConfigPath(cmd),
	}
}

func runClientServiceControl(action string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, _ []string) error {
		cfg := clientSvcConfig(cmd)
		d := internalsvc.NoopDaemon()
		switch action {
		case "install":
			if err := internalsvc.Install(d, cfg); err != nil {
				return err
			}
			fmt.Println("sigilc service installed successfully.")
			return nil
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

func runClientServiceStatus(cmd *cobra.Command, _ []string) error {
	cfg := clientSvcConfig(cmd)
	socket, err := clientIPCSocket(cmd)
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
