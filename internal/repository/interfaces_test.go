package repository_test

import (
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// The following typed nils reference every exported interface so that the
// package is exercised at compile time. This is an interfaces-only package, so
// there is no runtime behavior to test here; fakes and mocks live with the
// consuming packages.
var (
	_ repository.OwnerRepository             = nil
	_ repository.HandleRepository            = nil
	_ repository.DeviceRepository            = nil
	_ repository.PublicKeyRepository         = nil
	_ repository.KeySetRepository            = nil
	_ repository.AccessKeyRepository         = nil
	_ repository.RefreshCredentialRepository = nil
	_ repository.LinkedIdentityRepository    = nil
	_ repository.AuditAppender               = nil
	_ repository.AuditRepository             = nil
	_ repository.AdministratorRepository     = nil
	_ repository.Store                       = nil
)

// TestReposIsPlainStruct confirms Repos is a zero-usable struct whose fields can
// be assigned independently, as fakes rely on.
func TestReposIsPlainStruct(t *testing.T) {
	var r repository.Repos
	if r.Owners != nil || r.Audit != nil || r.Admins != nil {
		t.Fatal("zero-valued Repos should have nil fields")
	}
}

// TestPageZeroValue documents that a zero Page starts from the beginning with a
// non-positive Limit, leaving the default page size to the implementation.
func TestPageZeroValue(t *testing.T) {
	tests := []struct {
		name          string
		p             repository.Page
		wantAtDefault bool
	}{
		{name: "zero value", p: repository.Page{}, wantAtDefault: true},
		{name: "explicit limit", p: repository.Page{Limit: 50, Cursor: "abc"}, wantAtDefault: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			atDefault := tt.p.Limit <= 0
			if atDefault != tt.wantAtDefault {
				t.Fatalf("Limit=%d: atDefault=%v, want %v", tt.p.Limit, atDefault, tt.wantAtDefault)
			}
			if tt.name == "zero value" && tt.p.Cursor != "" {
				t.Fatalf("zero Page.Cursor = %q, want empty", tt.p.Cursor)
			}
		})
	}
}
