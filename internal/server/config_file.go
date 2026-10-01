package server

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Oganneson-Studio/certfold/internal/securefile"
)

// writeConfigFile atomically replaces the file at path with data. When path
// is a symbolic link, it replaces the file the link points to and keeps the
// link. On Unix the new file keeps the mode and owner of the file it
// replaces; on Windows it has the private DACL of securefile.CreateTemp.
func writeConfigFile(path string, data []byte) error {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	info, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	tmp, err := securefile.CreateTemp(filepath.Dir(target), ".certfold-private-*")
	if err != nil {
		return fmt.Errorf("write %s: %w", target, err)
	}
	tmpPath := tmp.Name()
	// The data is written while the file is still private.
	_, err = tmp.Write(data)
	if err == nil {
		err = keepMetadata(tmp, info)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmpPath, target)
	}
	if err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write %s: %w", target, err)
	}
	return nil
}
