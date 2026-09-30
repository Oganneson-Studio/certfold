package config

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// ErrCertificateNotFound is the error of RemoveCertificateSpec for a name no
// certificate has.
var ErrCertificateNotFound = errors.New("not found")

// AddCertificateSpec returns the server.yaml raw with spec appended to its
// certificates, and the configuration that parses from the result. The CA
// of spec defaults to acme.default_ca.
//
// It edits the YAML tree of raw instead of marshaling a parsed ServerConfig.
// Parsing expands ${ENV}; marshaling that value would persist secrets and
// destroy the placeholders in server.yaml.
func AddCertificateSpec(raw []byte, spec CertificateSpec) ([]byte, *ServerConfig, error) {
	cfg, doc, err := parseServerConfigDocument(raw)
	if err != nil {
		return nil, nil, err
	}
	for _, existing := range cfg.Certificates {
		if existing.Name == spec.Name {
			return nil, nil, fmt.Errorf("cert %q already exists", spec.Name)
		}
	}
	if spec.CA == "" {
		spec.CA = cfg.ACME.DefaultCA
	}

	seq, err := certificatesNode(doc, true)
	if err != nil {
		return nil, nil, err
	}
	var item yaml.Node
	if err := item.Encode(spec); err != nil {
		return nil, nil, fmt.Errorf("encode certificate %q: %w", spec.Name, err)
	}
	escapeDollarSigns(&item)
	seq.Content = append(seq.Content, &item)
	return encodeServerConfig(doc)
}

// RemoveCertificateSpec returns the server.yaml raw without the certificate
// named name, and the configuration that parses from the result. It
// preserves ${ENV} placeholders like AddCertificateSpec.
func RemoveCertificateSpec(raw []byte, name string) ([]byte, *ServerConfig, error) {
	cfg, doc, err := parseServerConfigDocument(raw)
	if err != nil {
		return nil, nil, err
	}
	index := -1
	for i, existing := range cfg.Certificates {
		if existing.Name == name {
			index = i
			break
		}
	}
	if index < 0 {
		return nil, nil, fmt.Errorf("cert %q %w", name, ErrCertificateNotFound)
	}

	seq, err := certificatesNode(doc, false)
	if err != nil {
		return nil, nil, err
	}
	if seq == nil || index >= len(seq.Content) {
		return nil, nil, fmt.Errorf("server config certificate layout is inconsistent")
	}
	seq.Content = append(seq.Content[:index], seq.Content[index+1:]...)
	return encodeServerConfig(doc)
}

// escapeDollarSigns doubles every '$' in the scalars under n, so values taken
// from the command line load back unchanged instead of being expanded as
// environment references.
func escapeDollarSigns(n *yaml.Node) {
	if n.Kind == yaml.ScalarNode {
		n.Value = strings.ReplaceAll(n.Value, "$", "$$")
	}
	for _, child := range n.Content {
		escapeDollarSigns(child)
	}
}

func parseServerConfigDocument(raw []byte) (*ServerConfig, *yaml.Node, error) {
	cfg, err := ParseServer(raw)
	if err != nil {
		return nil, nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, nil, fmt.Errorf("parse yaml document: %w", err)
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil, fmt.Errorf("server config root must be a mapping")
	}
	return cfg, &doc, nil
}

func certificatesNode(doc *yaml.Node, create bool) (*yaml.Node, error) {
	root := doc.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "certificates" {
			continue
		}
		value := root.Content[i+1]
		if create && value.Kind == yaml.ScalarNode && value.Tag == "!!null" {
			value.Kind = yaml.SequenceNode
			value.Tag = "!!seq"
			value.Value = ""
			value.Content = nil
		}
		if value.Kind != yaml.SequenceNode {
			return nil, fmt.Errorf("server config certificates must be a sequence")
		}
		return value, nil
	}
	if !create {
		return nil, nil
	}
	key := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "certificates"}
	value := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	root.Content = append(root.Content, key, value)
	return value, nil
}

// encodeServerConfig returns doc as YAML, and the configuration it parses
// into.
func encodeServerConfig(doc *yaml.Node) ([]byte, *ServerConfig, error) {
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, nil, fmt.Errorf("encode server config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, nil, fmt.Errorf("close server config encoder: %w", err)
	}
	cfg, err := ParseServer(out.Bytes())
	if err != nil {
		return nil, nil, fmt.Errorf("validate updated server config: %w", err)
	}
	return out.Bytes(), cfg, nil
}
