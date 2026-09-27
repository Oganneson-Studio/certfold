package config

import (
	"errors"
	"fmt"
	"strings"
)

// ValidationError aggregates multiple field-level errors from a Validate call.
type ValidationError struct {
	Errs []FieldError
}

type FieldError struct {
	Path string // dotted YAML path, e.g. "certificates[0].ca"
	Msg  string
}

func (e *ValidationError) Error() string {
	if len(e.Errs) == 0 {
		return "validation error"
	}
	parts := make([]string, len(e.Errs))
	for i, fe := range e.Errs {
		parts[i] = fmt.Sprintf("%s: %s", fe.Path, fe.Msg)
	}
	return "validation failed:\n  - " + strings.Join(parts, "\n  - ")
}

// Add appends a field error.
func (e *ValidationError) Add(path, format string, args ...any) {
	e.Errs = append(e.Errs, FieldError{Path: path, Msg: fmt.Sprintf(format, args...)})
}

// ErrOrNil returns nil if no errors were collected.
func (e *ValidationError) ErrOrNil() error {
	if len(e.Errs) == 0 {
		return nil
	}
	return e
}

// AsValidation extracts a *ValidationError from err, if present.
func AsValidation(err error) (*ValidationError, bool) {
	var v *ValidationError
	if errors.As(err, &v) {
		return v, true
	}
	return nil, false
}
