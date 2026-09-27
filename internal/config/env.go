package config

import (
	"fmt"
	"os"
	"strings"
)

// expandEnv substitutes ${VAR} and ${VAR:-default} in src using lookup.
// $$ produces a literal '$'. Returns an error if a referenced variable is
// unset and no default was provided.
func expandEnv(src []byte, lookup func(string) (string, bool)) ([]byte, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	var out strings.Builder
	out.Grow(len(src))

	for i := 0; i < len(src); {
		c := src[i]
		if c != '$' {
			out.WriteByte(c)
			i++
			continue
		}
		// '$' at end of input → literal
		if i+1 >= len(src) {
			out.WriteByte('$')
			i++
			continue
		}
		next := src[i+1]
		if next == '$' {
			out.WriteByte('$')
			i += 2
			continue
		}
		if next != '{' {
			out.WriteByte('$')
			i++
			continue
		}
		end := indexByte(src, i+2, '}')
		if end < 0 {
			return nil, fmt.Errorf("unterminated ${...} at offset %d", i)
		}
		spec := string(src[i+2 : end])
		name, def, hasDef := splitDefault(spec)
		if name == "" {
			return nil, fmt.Errorf("empty variable name at offset %d", i)
		}
		val, ok := lookup(name)
		if !ok {
			if hasDef {
				val = def
			} else {
				return nil, fmt.Errorf("environment variable %q is not set", name)
			}
		}
		out.WriteString(val)
		i = end + 1
	}
	return []byte(out.String()), nil
}

func indexByte(b []byte, from int, c byte) int {
	for i := from; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func splitDefault(spec string) (name, def string, hasDefault bool) {
	if idx := strings.Index(spec, ":-"); idx >= 0 {
		return spec[:idx], spec[idx+2:], true
	}
	return spec, "", false
}
