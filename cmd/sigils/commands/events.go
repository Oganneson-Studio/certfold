package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Oganneson-Studio/sigil/internal/logging"
)

func newEventsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "events",
		Short: "Print the recent events of the running sigils daemon",
		RunE:  runEvents,
	}
}

// runEvents prints the events the daemon keeps, oldest first; with --json,
// as a JSON array.
func runEvents(cmd *cobra.Command, _ []string) error {
	c, err := dialServer(cmd)
	if err != nil {
		return fmt.Errorf("ipc unavailable: %w", err)
	}
	page, err := c.Events(commandContext(cmd), 0)
	if err != nil {
		return err
	}
	if asJSON, _ := cmd.Root().PersistentFlags().GetBool("json"); asJSON {
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
