package config

import (
	"bytes"
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/Oganneson-Studio/sigil/internal/securefile"
)

var serverConfigEditMu sync.Mutex

// AddCertificateSpec appends spec to the server.yaml at path, filling the CA
// from acme.default_ca when it is empty, and returns the stored spec.
//
// It edits the raw YAML tree instead of marshaling a loaded ServerConfig.
// LoadServer expands ${ENV}; marshaling that value would persist secrets and
// destroy the placeholders in server.yaml.
func AddCertificateSpec(path string, spec CertificateSpec) (CertificateSpec, error) {
	serverConfigEditMu.Lock()
	defer serverConfigEditMu.Unlock()

	cfg, doc, err := loadServerConfigDocument(path)
	if err != nil {
		return CertificateSpec{}, err
	}
	for _, existing := range cfg.Certificates {
		if existing.Name == spec.Name {
			return CertificateSpec{}, fmt.Errorf("cert %q already exists", spec.Name)
		}
	}
	if spec.CA == "" {
		spec.CA = cfg.ACME.DefaultCA
	}

	seq, err := certificatesNode(doc, true)
	if err != nil {
		return CertificateSpec{}, err
	}
	var item yaml.Node
	if err := item.Encode(spec); err != nil {
		return CertificateSpec{}, fmt.Errorf("encode certificate %q: %w", spec.Name, err)
	}
	seq.Content = append(seq.Content, &item)

	if err := validateAndWriteServerConfig(path, doc); err != nil {
		return CertificateSpec{}, err
	}
	return spec, nil
}

// RemoveCertificateSpec deletes the certificate named name from the
// server.yaml at path, preserving ${ENV} placeholders like AddCertificateSpec.
func RemoveCertificateSpec(path, name string) error {
	serverConfigEditMu.Lock()
	defer serverConfigEditMu.Unlock()

	cfg, doc, err := loadServerConfigDocument(path)
	if err != nil {
		return err
	}
	index := -1
	for i, existing := range cfg.Certificates {
		if existing.Name == name {
			index = i
			break
		}
	}
	if index < 0 {
		return fmt.Errorf("cert %q not found", name)
	}

	seq, err := certificatesNode(doc, false)
	if err != nil {
		return err
	}
	if seq == nil || index >= len(seq.Content) {
		return fmt.Errorf("server config certificate layout is inconsistent")
	}
	seq.Content = append(seq.Content[:index], seq.Content[index+1:]...)
	return validateAndWriteServerConfig(path, doc)
}

func loadServerConfigDocument(path string) (*ServerConfig, *yaml.Node, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", path, err)
	}
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

func validateAndWriteServerConfig(path string, doc *yaml.Node) error {
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encode server config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("close server config encoder: %w", err)
	}
	if _, err := ParseServer(out.Bytes()); err != nil {
		return fmt.Errorf("validate updated server config: %w", err)
	}
	if err := securefile.WriteFile(path, out.Bytes()); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
