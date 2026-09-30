package version

import (
	"runtime/debug"
	"testing"
)

// TestFromBuildInfo covers a binary built without -ldflags, as go build and
// go install build it: its version is what the go command recorded, rather
// than a fixed placeholder that never changes. What the linker set stays.
func TestFromBuildInfo(t *testing.T) {
	version, commit := Version, Commit
	t.Cleanup(func() { Version, Commit = version, commit })
	info := &debug.BuildInfo{
		Main: debug.Module{Version: "v0.0.0-20260929071518-8c1189328a50+dirty"},
		Settings: []debug.BuildSetting{
			{Key: "vcs", Value: "git"},
			{Key: "vcs.revision", Value: "8c1189328a50e0ca035325ba0139708ab3ef7b89"},
			{Key: "vcs.time", Value: "2026-09-29T07:15:18Z"},
		},
	}

	Version, Commit = "", ""
	fromBuildInfo(info)
	if Version != info.Main.Version || Commit != "8c1189328a50e0ca035325ba0139708ab3ef7b89" {
		t.Errorf("without -ldflags: Version %q, Commit %q; want what the go command recorded", Version, Commit)
	}

	Version, Commit = "v1.2.3", "abc"
	fromBuildInfo(info)
	if Version != "v1.2.3" || Commit != "abc" {
		t.Errorf("with -ldflags: Version %q, Commit %q; want v1.2.3 and abc", Version, Commit)
	}
}

func TestStringNamesTheCommitWhenKnown(t *testing.T) {
	version, commit := Version, Commit
	t.Cleanup(func() { Version, Commit = version, commit })
	Version, Commit = "(devel)", ""
	if got := String(); got != "(devel)" {
		t.Errorf("String() without a commit = %q, want (devel)", got)
	}
	Version, Commit = "v1.2.3", "abc"
	if got := String(); got != "v1.2.3 (commit abc)" {
		t.Errorf("String() = %q, want v1.2.3 (commit abc)", got)
	}
}
