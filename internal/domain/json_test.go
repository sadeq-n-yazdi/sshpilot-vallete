package domain

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSecretHashNotSerialized(t *testing.T) {
	ak := AccessKey{
		ID:         "ak_1",
		SecretHash: []byte("super-secret-hash"),
	}
	data, err := json.Marshal(ak)
	if err != nil {
		t.Fatalf("marshal AccessKey: %v", err)
	}
	if strings.Contains(string(data), "SecretHash") || strings.Contains(string(data), "super-secret-hash") {
		t.Fatalf("AccessKey JSON leaked secret hash: %s", data)
	}

	rc := RefreshCredential{
		ID:         "rc_1",
		SecretHash: []byte("another-secret-hash"),
	}
	data, err = json.Marshal(rc)
	if err != nil {
		t.Fatalf("marshal RefreshCredential: %v", err)
	}
	if strings.Contains(string(data), "SecretHash") || strings.Contains(string(data), "another-secret-hash") {
		t.Fatalf("RefreshCredential JSON leaked secret hash: %s", data)
	}

	// A pairing carries two digests. The user code digest is the more dangerous
	// of the two to leak: a user code is short enough that its digest is
	// brute-forced in moments, so serializing it would hand over a live pairing.
	dp := DevicePairing{
		ID:             "dp_1",
		DeviceCodeHash: []byte("device-code-hash"),
		UserCodeHash:   []byte("user-code-hash"),
	}
	data, err = json.Marshal(dp)
	if err != nil {
		t.Fatalf("marshal DevicePairing: %v", err)
	}
	for _, leak := range []string{"DeviceCodeHash", "device-code-hash", "UserCodeHash", "user-code-hash"} {
		if strings.Contains(string(data), leak) {
			t.Fatalf("DevicePairing JSON leaked %q: %s", leak, data)
		}
	}
}
