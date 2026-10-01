package main

import (
	"fmt"
	"os"

	"github.com/Oganneson-Studio/certfold/cmd/certfoldc/commands"
	"github.com/Oganneson-Studio/certfold/internal/logging"
)

func main() {
	if err := commands.NewRootCmd().Execute(); err != nil {
		// Errors can quote the network, such as the DNS names in the
		// certificate of a man in the middle.
		fmt.Fprintln(os.Stderr, "error:", logging.Printable(err.Error()))
		os.Exit(1)
	}
}
