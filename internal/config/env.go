package config

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// decodeWithEnv parses raw as YAML, expands ${VAR}, ${VAR:-default} and $$
// inside scalar values, and decodes the result into out, rejecting unknown
// fields. Expanding after parsing makes every environment value one literal
// scalar: quotes, backslashes, '#' or ": " inside it are never read as YAML.
func decodeWithEnv(raw []byte, out any) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("parse yaml: %w", err)
	}
	if err := expandEnvNode(&doc, ""); err != nil {
		return fmt.Errorf("expand env: %w", err)
	}
	// yaml.v3 enforces KnownFields only while decoding a byte stream, so the
	// expanded tree is encoded again. Line numbers in decode errors therefore
	// refer to that normalized document, not to raw: blank lines are dropped
	// and block scalars are written on one line.
	quoteStringScalars(&doc)
	expanded, err := yaml.Marshal(&doc)
	if err != nil {
		return fmt.Errorf("encode expanded yaml: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(expanded))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("parse yaml: %w", err)
	}
	return nil
}

// quoteStringScalars switches block scalars, and scalars whose value contains
// a line break, to double-quoted style. yaml.v3 does not re-emit those exactly
// (leading or only line breaks, tab-indented lines, keep chomping), while a
// double-quoted scalar escapes every character. Only the presentation
// changes: all of these scalars are strings.
func quoteStringScalars(n *yaml.Node) {
	if n.Kind == yaml.ScalarNode &&
		(n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 ||
			strings.ContainsAny(n.Value, "\n\r\u0085\u2028\u2029")) {
		n.Style = n.Style&yaml.TaggedStyle | yaml.DoubleQuotedStyle
	}
	for _, child := range n.Content {
		quoteStringScalars(child)
	}
}

// expandEnvNode expands environment references in every scalar value under n,
// in place. Values are inserted verbatim, so leading and trailing spaces and
// line breaks are kept. Mapping keys are never expanded, and aliases are
// skipped because the node they refer to is expanded where it is defined.
// Errors name the YAML path of the value, such as dns_providers.cf.api_token
// or certificates[0].subscribers[1].
func expandEnvNode(n *yaml.Node, path string) error {
	switch n.Kind {
	case yaml.DocumentNode:
		for _, child := range n.Content {
			if err := expandEnvNode(child, path); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			childPath := n.Content[i].Value
			if path != "" {
				childPath = path + "." + childPath
			}
			if err := expandEnvNode(n.Content[i+1], childPath); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for i, child := range n.Content {
			if err := expandEnvNode(child, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		value, err := expandEnv(n.Value, nil)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if value != n.Value {
			n.Value = value
			// The parser tagged the unexpanded text, so "${SKIP}" is a !!str.
			// Clearing the tag of a plain scalar makes YAML resolve the
			// expanded text as if it had been written literally, so
			// skip_propagation_check: ${SKIP} still decodes as a bool. Quoted
			// and block scalars, and explicitly tagged ones, keep their tag.
			if n.Style == 0 {
				n.Tag = ""
			}
		}
	}
	return nil
}

// expandEnv substitutes ${VAR} and ${VAR:-default} in s using lookup
// (os.LookupEnv when nil). $$ produces a literal '$'. Returns an error if a
// referenced variable is unset and no default was provided.
func expandEnv(s string, lookup func(string) (string, bool)) (string, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	var out strings.Builder
	out.Grow(len(s))

	for i := 0; i < len(s); {
		c := s[i]
		if c != '$' {
			out.WriteByte(c)
			i++
			continue
		}
		// '$' at end of input → literal
		if i+1 >= len(s) {
			out.WriteByte('$')
			i++
			continue
		}
		next := s[i+1]
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
		end := strings.IndexByte(s[i+2:], '}')
		if end < 0 {
			return "", fmt.Errorf("unterminated ${...} at offset %d", i)
		}
		end += i + 2
		spec := s[i+2 : end]
		name, def, hasDef := splitDefault(spec)
		if name == "" {
			return "", fmt.Errorf("empty variable name at offset %d", i)
		}
		val, ok := lookup(name)
		if !ok {
			if hasDef {
				val = def
			} else {
				return "", fmt.Errorf("environment variable %q is not set", name)
			}
		}
		out.WriteString(val)
		i = end + 1
	}
	return out.String(), nil
}

func splitDefault(spec string) (name, def string, hasDefault bool) {
	if idx := strings.Index(spec, ":-"); idx >= 0 {
		return spec[:idx], spec[idx+2:], true
	}
	return spec, "", false
}
