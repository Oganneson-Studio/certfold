package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/Oganneson-Studio/certfold/internal/securefile"
)

// storeFileName names the private store in client.data_dir. The server's
// certificate names only key its entries: no path depends on them.
const storeFileName = "certs.json"

// storedCert is the material of one certificate in the store.
type storedCert struct {
	// Fingerprint is the one the bundle response carried with this material.
	Fingerprint  string `json:"fingerprint"`
	FullchainPEM string `json:"fullchain_pem"`
	KeyPEM       string `json:"key_pem"`
	// HookPending records that the certificate's on_change program must run:
	// its material changed or the content of one of its outputs was
	// rewritten, and the program has not succeeded since.
	HookPending bool `json:"hook_pending,omitempty"`
}

// storeFile is the JSON document in certs.json.
type storeFile struct {
	Certs map[string]storedCert `json:"certs"`
}

// loadStore reads the store in dataDir. A missing file is an empty store. An
// existing one is made private before it is read, as certfolds tightens its
// SQLite files when it reopens them. A file that is not valid JSON is logged
// and read as an empty store: the next sync downloads the material again,
// and only the pending on_change runs are lost.
func loadStore(dataDir string) (map[string]storedCert, error) {
	path := filepath.Join(dataDir, storeFileName)
	if err := securefile.ProtectFile(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]storedCert{}, nil
		}
		return nil, fmt.Errorf("protect %s: %w", path, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var file storeFile
	if err := json.Unmarshal(data, &file); err != nil {
		slog.Warn("certificate store is not valid; starting empty", "path", path, "error", err)
		return map[string]storedCert{}, nil
	}
	if file.Certs == nil {
		file.Certs = map[string]storedCert{}
	}
	return file.Certs, nil
}

// saveStore replaces the store in dataDir with certs. The file holds private
// keys, so it is written only through securefile.
func saveStore(dataDir string, certs map[string]storedCert) error {
	data, err := json.Marshal(storeFile{Certs: certs})
	if err != nil {
		return err
	}
	return securefile.WriteFile(filepath.Join(dataDir, storeFileName), data)
}
