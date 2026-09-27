package service

import "embed"

// clientBinaries holds the bundled sigilc binaries for all platforms.
// During a release build, the dist/ directory is populated with
// sigilc-{os}-{arch} (and sigilc-{os}-{arch}.exe on Windows) before `go build`.
// For a plain development build the directory is empty, causing UnpackClients
// to emit a warning instead of writing any files.
//
//go:embed dist
var clientBinaries embed.FS

// ClientBinariesFS returns the embedded FS containing bundled sigilc binaries.
// Callers should pass the returned FS to UnpackClients.
func ClientBinariesFS() embed.FS {
	return clientBinaries
}
