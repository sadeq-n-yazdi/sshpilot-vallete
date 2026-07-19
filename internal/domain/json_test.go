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
}
