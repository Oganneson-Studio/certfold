package service

import (
	"runtime"
	"slices"
	"strings"
	"testing"
)

// TestSystemdUnitRestartsAfterFiveSeconds guards the unit that replaces the
// one kardianos writes by default, which waits 120 seconds before restarting
// a failed daemon.
func TestSystemdUnitRestartsAfterFiveSeconds(t *testing.T) {
	lines := strings.Split(systemdUnit, "\n")
	for _, want := range []string{"Restart=on-failure", "RestartSec=5"} {
		if !slices.Contains(lines, want) {
			t.Errorf("unit lacks the line %q:\n%s", want, systemdUnit)
		}
	}
	if strings.Contains(systemdUnit, "RestartSec=120") {
		t.Errorf("unit waits 120 seconds to restart:\n%s", systemdUnit)
	}
	// The option only reaches kardianos on Linux.
	if runtime.GOOS == "linux" {
		if got := buildServiceConfig(Config{Role: RoleServer}).Option["SystemdScript"]; got != systemdUnit {
			t.Errorf("SystemdScript option = %q, want the unit", got)
		}
	}
}
