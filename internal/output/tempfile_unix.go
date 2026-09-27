//go:build !windows

package output

import (
	"os"

	"github.com/Oganneson-Studio/sigil/internal/config"
)

// createTemp creates the temporary file for an output in dir. os.CreateTemp
// creates it with mode 0600, so it stays private until applyMode sets the
// output mode.
func createTemp(dir string, _ config.OutputSpec) (*os.File, error) {
	return os.CreateTemp(dir, ".sigil-tmp-*")
}

// applyMode gives the temporary file the output's permission bits.
func applyMode(tmp *os.File, spec config.OutputSpec) error {
	return tmp.Chmod(os.FileMode(outputMode(spec)))
}
