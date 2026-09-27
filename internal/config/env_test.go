package config

import (
	"strings"
	"testing"
)

func TestExpandEnv(t *testing.T) {
	env := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) {
			v, ok := m[k]
			return v, ok
		}
	}

	tests := []struct {
		name    string
		in      string
		lookup  func(string) (string, bool)
		want    string
		wantErr string
	}{
		{
			name:   "no substitution",
			in:     "hello: world",
			lookup: env(nil),
			want:   "hello: world",
		},
		{
			name:   "simple var",
			in:     "token: ${TOKEN}",
			lookup: env(map[string]string{"TOKEN": "abc123"}),
			want:   "token: abc123",
		},
		{
			name:   "default when unset",
			in:     "token: ${MISSING:-fallback}",
			lookup: env(nil),
			want:   "token: fallback",
		},
		{
			name:   "default ignored when set",
			in:     "token: ${TOKEN:-fallback}",
			lookup: env(map[string]string{"TOKEN": "real"}),
			want:   "token: real",
		},
		{
			name:   "literal dollar via $$",
			in:     "regex: $$start",
			lookup: env(nil),
			want:   "regex: $start",
		},
		{
			name:   "lonely dollar passes through",
			in:     "price: $5",
			lookup: env(nil),
			want:   "price: $5",
		},
		{
			name:    "unset without default errors",
			in:      "token: ${MISSING}",
			lookup:  env(nil),
			wantErr: `environment variable "MISSING" is not set`,
		},
		{
			name:    "unterminated braces error",
			in:      "broken: ${OPEN",
			lookup:  env(nil),
			wantErr: "unterminated",
		},
		{
			name:    "empty name errors",
			in:      "bad: ${}",
			lookup:  env(nil),
			wantErr: "empty variable name",
		},
		{
			name:   "multiple substitutions",
			in:     "a: ${A}, b: ${B:-def}, c: ${C}",
			lookup: env(map[string]string{"A": "1", "C": "3"}),
			want:   "a: 1, b: def, c: 3",
		},
		{
			name:   "default with empty value",
			in:     "x: ${X:-}",
			lookup: env(nil),
			want:   "x: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := expandEnv([]byte(tt.in), tt.lookup)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, string(got))
			}
		})
	}
}
