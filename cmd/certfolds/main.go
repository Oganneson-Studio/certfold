package main

import (
	"fmt"
	"os"

	"github.com/Oganneson-Studio/certfold/cmd/certfolds/commands"
	"github.com/Oganneson-Studio/certfold/internal/logging"
)

func main() {
	if err := commands.NewRootCmd().Execute(); err != nil {
		// Errors can quote files, and answers of the daemon that quote the
		// network, such as the errors of a manual renewal.
		fmt.Fprintln(os.Stderr, "error:", logging.Printable(err.Error()))
		os.Exit(1)
	}
}
