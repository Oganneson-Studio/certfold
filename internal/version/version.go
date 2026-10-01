// Package version identifies the build of the binary.
package version

import "runtime/debug"

// Version and Commit identify the build. A release build may set them with
// -ldflags "-X github.com/Oganneson-Studio/certfold/internal/version.Version=...".
// Otherwise they are what the go command recorded in the binary: the version
// of the main module, which go build derives from the Git checkout (a
// pseudo-version that ends in +dirty when the checkout had uncommitted
// changes, or "(devel)" when it could not tell), and the full hash of the
// commit, empty when it could not tell.
var Version, Commit string

func init() {
	if info, ok := debug.ReadBuildInfo(); ok {
		fromBuildInfo(info)
	}
}

// String returns Version, followed by the commit when it is known.
func String() string {
	if Commit == "" {
		return Version
	}
	return Version + " (commit " + Commit + ")"
}

// fromBuildInfo sets Version and Commit from info where the linker did not
// set them.
func fromBuildInfo(info *debug.BuildInfo) {
	if Version == "" {
		Version = info.Main.Version
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && Commit == "" {
			Commit = s.Value
		}
	}
}
