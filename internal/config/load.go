package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"gopkg.in/yaml.v3"
)

// Load builds a Config with precedence env > file > built-in defaults:
//
//  1. start from Default();
//  2. if path is non-empty and the file exists, decode it over the defaults
//     with KnownFields(true) so an unknown yaml key is a hard error;
//  3. overlay environment variables (VALLET_*) via the binding table.
//
// Load returns the merged config WITHOUT validating it; callers must call
// (*Config).Validate separately. A missing file at a non-empty path is an
// error (an explicitly named config file must exist); pass "" to load from
// defaults and environment only. Only the given path is consulted — Load does
// not search default locations.
func Load(path string) (*Config, error) {
	cfg := Default()

	if path != "" {
		if err := decodeFile(path, &cfg); err != nil {
			return nil, err
		}
	}

	if err := applyEnv(&cfg, os.LookupEnv); err != nil {
		return nil, fmt.Errorf("config: environment overrides: %w", err)
	}

	return &cfg, nil
}

// decodeFile decodes the yaml file at path over cfg, rejecting unknown keys.
func decodeFile(path string, cfg *Config) error {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("config: file %q does not exist", path)
		}
		return fmt.Errorf("config: open %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return fmt.Errorf("config: decode %q: %w", path, err)
	}
	return nil
}
