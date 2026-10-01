package commands

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Oganneson-Studio/certfold/internal/logging"
)

func newEventsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "events",
		Short: "Print the recent events of the running certfoldc daemon",
		RunE:  runEvents,
	}
	cmd.Flags().Bool("json", false, "emit machine-readable JSON")
	return cmd
}

// runEvents prints the events the daemon keeps, oldest first; with --json,
// as a JSON array.
func runEvents(cmd *cobra.Command, _ []string) error {
	c, err := dialDaemon(cmd)
	if err != nil {
		return err
	}
	page, err := c.Events(context.Background(), 0)
	if err != nil {
		return err
	}
	if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
		return printJSON(page.Events)
	}
	for _, e := range page.Events {
		fmt.Println(formatEvent(e))
	}
	return nil
}

// formatEvent formats e as "2006-01-02 15:04:05  INFO   message  attrs" in
// local time.
func formatEvent(e logging.Event) string {
	line := fmt.Sprintf("%s  %-5s  %s", e.Time.Local().Format("2006-01-02 15:04:05"), e.Level, e.Message)
	if e.Attrs != "" {
		line += "  " + e.Attrs
	}
	return line
}
