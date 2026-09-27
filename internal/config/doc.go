// Package config loads, validates, and exposes server.yaml and client.yaml.
//
// It is the single source of truth on disk; the daemon derives all runtime
// state from these structures.
package config
