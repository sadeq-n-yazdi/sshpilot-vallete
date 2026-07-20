package auth_test

import (
	"errors"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

func TestNewRegistry(t *testing.T) {
	tests := []struct {
		name      string
		providers []auth.AuthProvider
		wantErr   error
		wantLen   int
	}{
		{name: "empty registry is valid", providers: nil, wantLen: 0},
		{
			name:      "single provider",
			providers: []auth.AuthProvider{&fakeProvider{id: "api-token"}},
			wantLen:   1,
		},
		{
			name: "distinct providers",
			providers: []auth.AuthProvider{
				&fakeProvider{id: "api-token"},
				&fakeProvider{id: "webauthn"},
				&fakeProvider{id: "oidc"},
			},
			wantLen: 3,
		},
		{
			name:      "nil provider rejected",
			providers: []auth.AuthProvider{nil},
			wantErr:   domain.ErrInvalidInput,
		},
		{
			name:      "malformed provider id rejected",
			providers: []auth.AuthProvider{&fakeProvider{id: "API:Token"}},
			wantErr:   domain.ErrInvalidInput,
		},
		{
			name:      "empty provider id rejected",
			providers: []auth.AuthProvider{&fakeProvider{id: ""}},
			wantErr:   domain.ErrInvalidInput,
		},
		{
			// Two providers sharing an id would share a principal namespace.
			// Startup must refuse rather than silently keep one of them.
			name: "duplicate provider id rejected",
			providers: []auth.AuthProvider{
				&fakeProvider{id: "oidc"},
				&fakeProvider{id: "oidc"},
			},
			wantErr: domain.ErrConflict,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg, err := auth.NewRegistry(tt.providers...)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("NewRegistry error = %v, want %v", err, tt.wantErr)
				}
				if reg != nil {
					t.Fatal("NewRegistry returned a registry alongside an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewRegistry: %v", err)
			}
			if got := reg.Len(); got != tt.wantLen {
				t.Fatalf("Len() = %d, want %d", got, tt.wantLen)
			}
		})
	}
}

func TestRegistryLookup(t *testing.T) {
	want := &fakeProvider{id: "api-token"}
	reg, err := auth.NewRegistry(want, &fakeProvider{id: "oidc"})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	got, err := reg.Lookup("api-token")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got != auth.AuthProvider(want) {
		t.Fatal("Lookup returned a different provider instance")
	}

	// Every miss, whether unregistered or malformed, must be the same opaque
	// denial: a caller must not be able to enumerate configured providers.
	misses := []auth.ProviderID{"webauthn", "", "API-TOKEN", "api:token"}
	for _, id := range misses {
		t.Run("miss "+string(id), func(t *testing.T) {
			p, err := reg.Lookup(id)
			if p != nil {
				t.Fatal("Lookup returned a provider for a miss")
			}
			if !errors.Is(err, auth.ErrAuthFailed) {
				t.Fatalf("Lookup error = %v, want auth.ErrAuthFailed", err)
			}
			if err.Error() != auth.ErrAuthFailed.Error() {
				t.Fatalf("Lookup error text %q differs from the sentinel", err.Error())
			}
		})
	}
}

// TestRegistryIsIsolatedFromCallerSlice confirms the registry copies what it
// needs at construction, so mutating the caller's slice afterwards cannot swap
// in a provider the server never registered.
func TestRegistryIsIsolatedFromCallerSlice(t *testing.T) {
	providers := []auth.AuthProvider{&fakeProvider{id: "api-token"}}
	reg, err := auth.NewRegistry(providers...)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	providers[0] = &fakeProvider{id: "evil"}

	if _, err := reg.Lookup("evil"); !errors.Is(err, auth.ErrAuthFailed) {
		t.Fatal("mutating the caller slice registered a new provider")
	}
	if _, err := reg.Lookup("api-token"); err != nil {
		t.Fatalf("original provider lost after caller mutated its slice: %v", err)
	}
}
