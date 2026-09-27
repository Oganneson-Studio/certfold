package main

import (
	"fmt"
	"os"

	"github.com/Oganneson-Studio/sigil/cmd/sigilc/commands"
)

func main() {
	if err := commands.NewRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
