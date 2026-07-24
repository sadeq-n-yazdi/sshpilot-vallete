package domain

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSentinelErrorsDistinct(t *testing.T) {
	all := []error{
		ErrNotFound, ErrConflict, ErrInvalidInput, ErrUnauthorized, ErrForbidden,
		ErrQuarantined, ErrBlockedName, ErrRevoked, ErrExpired, ErrImmutable,
		ErrLimitExceeded, ErrDefaultKeySet,
	}
	for i := range all {
		if all[i] == nil {
			t.Fatalf("sentinel at index %d is nil", i)
		}
		if !strings.HasPrefix(all[i].Error(), "domain: ") {
			t.Errorf("error %q is not prefixed with \"domain: \"", all[i].Error())
		}
		for j := range all {
			if i != j && errors.Is(all[i], all[j]) {
				t.Errorf("sentinels %q and %q are not distinct", all[i], all[j])
			}
		}
	}
}

func TestSentinelWrapping(t *testing.T) {
	wrapped := fmt.Errorf("resolving handle: %w", ErrNotFound)
	if !errors.Is(wrapped, ErrNotFound) {
		t.Fatalf("wrapped error should match ErrNotFound")
	}
	if errors.Is(wrapped, ErrConflict) {
		t.Fatalf("wrapped error should not match ErrConflict")
	}
}
