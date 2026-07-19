package domain

import "testing"

// enumCase pairs a validity expectation with an IsValid result.
type enumCase struct {
	name  string
	valid bool
	got   bool
}

func checkEnum(t *testing.T, cases []enumCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.valid {
				t.Fatalf("IsValid = %v, want %v", tc.got, tc.valid)
			}
		})
	}
}

// TestEnumWireValues pins the literal string value of every enum constant.
// These strings are the persistence and API contract other packages build on;
// IsValid tests cannot catch a typo because the switch compares a const to
// itself.
func TestEnumWireValues(t *testing.T) {
	cases := []struct {
		got  string
		want string
	}{
		{string(OwnerStatusActive), "active"},
		{string(OwnerStatusSuspended), "suspended"},
		{string(OwnerStatusDeleted), "deleted"},
		{string(NameStateActive), "active"},
		{string(NameStateQuarantined), "quarantined"},
		{string(NameStateRetired), "retired"},
		{string(DeviceStatusActive), "active"},
		{string(DeviceStatusRevoked), "revoked"},
		{string(AlgEd25519), "ssh-ed25519"},
		{string(AlgECDSA256), "ecdsa-sha2-nistp256"},
		{string(AlgECDSA384), "ecdsa-sha2-nistp384"},
		{string(AlgECDSA521), "ecdsa-sha2-nistp521"},
		{string(AlgRSA), "ssh-rsa"},
		{string(AlgSKEd25519), "sk-ssh-ed25519@openssh.com"},
		{string(AlgSKECDSA256), "sk-ecdsa-sha2-nistp256@openssh.com"},
		{string(KeyStatusActive), "active"},
		{string(KeyStatusRevoked), "revoked"},
		{string(VisibilityPublic), "public"},
		{string(VisibilityProtected), "protected"},
		{string(AccessKeyStatusActive), "active"},
		{string(AccessKeyStatusGrace), "grace"},
		{string(AccessKeyStatusRevoked), "revoked"},
		{string(CredentialStatusActive), "active"},
		{string(CredentialStatusRotated), "rotated"},
		{string(CredentialStatusRevoked), "revoked"},
		{string(CredentialStatusExpired), "expired"},
		{string(ScopeFullOwner), "full-owner"},
		{string(ScopeReadOnly), "read-only"},
		{string(ScopeSingleSet), "single-set"},
		{string(ScopeSingleDevice), "single-device"},
		{string(ActorTypeOwner), "owner"},
		{string(ActorTypeAdministrator), "administrator"},
		{string(ActorTypeSystem), "system"},
		{string(TargetTypeOwner), "owner"},
		{string(TargetTypeHandle), "handle"},
		{string(TargetTypeDevice), "device"},
		{string(TargetTypePublicKey), "public_key"},
		{string(TargetTypeKeySet), "key_set"},
		{string(TargetTypeAccessKey), "access_key"},
		{string(TargetTypeRefreshCredential), "refresh_credential"},
		{string(TargetTypeBlocklistEntry), "blocklist_entry"},
		{string(TargetTypeAllowlistEntry), "allowlist_entry"},
		{string(AdminStatusActive), "active"},
		{string(AdminStatusDisabled), "disabled"},
		{string(AuditActionKeySetVisibilityChanged), "key_set.visibility_changed"},
		{string(AuditActionCredentialReuseDetected), "credential.reuse_detected"},
		{string(AuditActionAuditPseudonymized), "audit.pseudonymized"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("enum wire value = %q, want %q", c.got, c.want)
		}
	}
}

func TestOwnerStatusIsValid(t *testing.T) {
	checkEnum(t, []enumCase{
		{"active", true, OwnerStatusActive.IsValid()},
		{"suspended", true, OwnerStatusSuspended.IsValid()},
		{"deleted", true, OwnerStatusDeleted.IsValid()},
		{"empty", false, OwnerStatus("").IsValid()},
		{"unknown", false, OwnerStatus("frozen").IsValid()},
	})
}

func TestNameStateIsValid(t *testing.T) {
	checkEnum(t, []enumCase{
		{"active", true, NameStateActive.IsValid()},
		{"quarantined", true, NameStateQuarantined.IsValid()},
		{"retired", true, NameStateRetired.IsValid()},
		{"empty", false, NameState("").IsValid()},
		{"unknown", false, NameState("banned").IsValid()},
	})
}

func TestDeviceStatusIsValid(t *testing.T) {
	checkEnum(t, []enumCase{
		{"active", true, DeviceStatusActive.IsValid()},
		{"revoked", true, DeviceStatusRevoked.IsValid()},
		{"empty", false, DeviceStatus("").IsValid()},
		{"unknown", false, DeviceStatus("lost").IsValid()},
	})
}

func TestAlgorithmIsValid(t *testing.T) {
	checkEnum(t, []enumCase{
		{"ed25519", true, AlgEd25519.IsValid()},
		{"ecdsa256", true, AlgECDSA256.IsValid()},
		{"ecdsa384", true, AlgECDSA384.IsValid()},
		{"ecdsa521", true, AlgECDSA521.IsValid()},
		{"rsa", true, AlgRSA.IsValid()},
		{"sk-ed25519", true, AlgSKEd25519.IsValid()},
		{"sk-ecdsa256", true, AlgSKECDSA256.IsValid()},
		{"empty", false, Algorithm("").IsValid()},
		{"dsa rejected", false, Algorithm("ssh-dss").IsValid()},
		{"unknown", false, Algorithm("ssh-rsa2").IsValid()},
	})
}

func TestKeyStatusIsValid(t *testing.T) {
	checkEnum(t, []enumCase{
		{"active", true, KeyStatusActive.IsValid()},
		{"revoked", true, KeyStatusRevoked.IsValid()},
		{"empty", false, KeyStatus("").IsValid()},
		{"unknown", false, KeyStatus("stale").IsValid()},
	})
}

func TestVisibilityIsValid(t *testing.T) {
	checkEnum(t, []enumCase{
		{"public", true, VisibilityPublic.IsValid()},
		{"protected", true, VisibilityProtected.IsValid()},
		{"empty", false, Visibility("").IsValid()},
		{"private unknown", false, Visibility("private").IsValid()},
	})
}

func TestAccessKeyStatusIsValid(t *testing.T) {
	checkEnum(t, []enumCase{
		{"active", true, AccessKeyStatusActive.IsValid()},
		{"grace", true, AccessKeyStatusGrace.IsValid()},
		{"revoked", true, AccessKeyStatusRevoked.IsValid()},
		{"empty", false, AccessKeyStatus("").IsValid()},
		{"unknown", false, AccessKeyStatus("expired").IsValid()},
	})
}

func TestCredentialStatusIsValid(t *testing.T) {
	checkEnum(t, []enumCase{
		{"active", true, CredentialStatusActive.IsValid()},
		{"rotated", true, CredentialStatusRotated.IsValid()},
		{"revoked", true, CredentialStatusRevoked.IsValid()},
		{"expired", true, CredentialStatusExpired.IsValid()},
		{"empty", false, CredentialStatus("").IsValid()},
		{"unknown", false, CredentialStatus("grace").IsValid()},
	})
}

func TestScopeKindIsValid(t *testing.T) {
	checkEnum(t, []enumCase{
		{"full-owner", true, ScopeFullOwner.IsValid()},
		{"read-only", true, ScopeReadOnly.IsValid()},
		{"single-set", true, ScopeSingleSet.IsValid()},
		{"single-device", true, ScopeSingleDevice.IsValid()},
		{"empty", false, ScopeKind("").IsValid()},
		{"unknown", false, ScopeKind("admin").IsValid()},
	})
}

func TestActorTypeIsValid(t *testing.T) {
	checkEnum(t, []enumCase{
		{"owner", true, ActorTypeOwner.IsValid()},
		{"administrator", true, ActorTypeAdministrator.IsValid()},
		{"system", true, ActorTypeSystem.IsValid()},
		{"empty", false, ActorType("").IsValid()},
		{"unknown", false, ActorType("robot").IsValid()},
	})
}

func TestTargetTypeIsValid(t *testing.T) {
	checkEnum(t, []enumCase{
		{"owner", true, TargetTypeOwner.IsValid()},
		{"handle", true, TargetTypeHandle.IsValid()},
		{"device", true, TargetTypeDevice.IsValid()},
		{"public_key", true, TargetTypePublicKey.IsValid()},
		{"key_set", true, TargetTypeKeySet.IsValid()},
		{"access_key", true, TargetTypeAccessKey.IsValid()},
		{"refresh_credential", true, TargetTypeRefreshCredential.IsValid()},
		{"blocklist_entry", true, TargetTypeBlocklistEntry.IsValid()},
		{"allowlist_entry", true, TargetTypeAllowlistEntry.IsValid()},
		{"empty", false, TargetType("").IsValid()},
		{"unknown", false, TargetType("session").IsValid()},
	})
}

func TestAdminStatusIsValid(t *testing.T) {
	checkEnum(t, []enumCase{
		{"active", true, AdminStatusActive.IsValid()},
		{"disabled", true, AdminStatusDisabled.IsValid()},
		{"empty", false, AdminStatus("").IsValid()},
		{"unknown", false, AdminStatus("locked").IsValid()},
	})
}
