package config

import (
	"path/filepath"
	"testing"
)

// TestExampleFileLoads guards the repo-root vallet.example.yaml against schema
// drift: Load uses KnownFields(true), so a renamed or stray key here fails.
func TestExampleFileLoads(t *testing.T) {
	path := filepath.Join("..", "..", "vallet.example.yaml")
	if _, err := Load(path); err != nil {
		t.Fatalf("vallet.example.yaml is out of sync with the schema: %v", err)
	}
}
