// Package config reads service configuration from environment variables.
// Every setting has a typed accessor with a default, and parse errors are
// collected so a service can report all bad settings at once on startup.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Env reads ARGUS_* style variables. Lookup defaults to os.LookupEnv and is
// replaceable in tests.
type Env struct {
	Prefix string
	Lookup func(string) (string, bool)
	errs   []error
}

// New returns an Env for the given prefix (for example "ARGUS_").
func New(prefix string) *Env { return &Env{Prefix: prefix, Lookup: os.LookupEnv} }

func (e *Env) get(key string) (string, bool) {
	v, ok := e.Lookup(e.Prefix + key)
	if !ok {
		return "", false
	}
	v = strings.TrimSpace(v)
	return v, v != ""
}

// String returns the value or def.
func (e *Env) String(key, def string) string {
	if v, ok := e.get(key); ok {
		return v
	}
	return def
}

// File returns the contents of the file named by KEY_FILE when set, else the
// value of KEY, else def. This is how secrets mounted by Kubernetes are read.
func (e *Env) File(key, def string) string {
	if path, ok := e.get(key + "_FILE"); ok {
		b, err := os.ReadFile(path)
		if err != nil {
			e.errs = append(e.errs, fmt.Errorf("%s%s_FILE: %w", e.Prefix, key, err))
			return def
		}
		return strings.TrimSpace(string(b))
	}
	return e.String(key, def)
}

// Int returns the integer value or def.
func (e *Env) Int(key string, def int) int {
	v, ok := e.get(key)
	if !ok {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s%s: not an integer: %q", e.Prefix, key, v))
		return def
	}
	return n
}

// Bool returns the boolean value or def.
func (e *Env) Bool(key string, def bool) bool {
	v, ok := e.get(key)
	if !ok {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s%s: not a boolean: %q", e.Prefix, key, v))
		return def
	}
	return b
}

// Duration returns a Go duration ("30s", "5m") or def.
func (e *Env) Duration(key string, def time.Duration) time.Duration {
	v, ok := e.get(key)
	if !ok {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s%s: not a duration: %q", e.Prefix, key, v))
		return def
	}
	return d
}

// List returns a comma-separated list or def.
func (e *Env) List(key string, def []string) []string {
	v, ok := e.get(key)
	if !ok {
		return def
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Require records an error when a required value is empty.
func (e *Env) Require(key, value string) {
	if value == "" {
		e.errs = append(e.errs, fmt.Errorf("%s%s is required", e.Prefix, key))
	}
}

// Err returns every collected error, or nil.
func (e *Env) Err() error { return errors.Join(e.errs...) }
