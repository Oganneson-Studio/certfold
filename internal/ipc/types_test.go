package ipc

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// A time that has not happened yet is left out of the JSON rather than
// written as 0001-01-01T00:00:00Z, which omitempty does not do for a
// time.Time.
func TestUnsetTimesAreLeftOut(t *testing.T) {
	at := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name  string
		value any
		field string
		set   any
	}{
		{"last pull", ClientState{Name: "web-1"}, `"last_pull_at"`, ClientState{Name: "web-1", LastPullAt: at}},
		{"token use", TokenInfo{TokenID: "t1", ExpiresAt: at, CreatedAt: at}, `"used_at"`, TokenInfo{TokenID: "t1", ExpiresAt: at, UsedAt: at, CreatedAt: at}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unset, err := json.Marshal(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(unset), tc.field) {
				t.Errorf("unset: %s holds %s", unset, tc.field)
			}
			set, err := json.Marshal(tc.set)
			if err != nil {
				t.Fatal(err)
			}
			if want := tc.field + `:"2026-09-29T10:00:00Z"`; !strings.Contains(string(set), want) {
				t.Errorf("set: %s lacks %s", set, want)
			}
		})
	}
}
