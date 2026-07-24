package httpserver

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// unauthorizingListAdmin refuses the empty actor exactly as listadmin does, so
// the coerced deny-all path can be observed as a uniform 403.
type unauthorizingListAdmin struct{}

func (unauthorizingListAdmin) AddAllowlistEntry(_ context.Context, a domain.AdministratorID, _ string) error {
	return refuseEmpty(a)
}
func (unauthorizingListAdmin) RemoveAllowlistEntry(_ context.Context, a domain.AdministratorID, _ string) error {
	return refuseEmpty(a)
}
func (unauthorizingListAdmin) AddBlocklistTerm(_ context.Context, a domain.AdministratorID, _ string) error {
	return refuseEmpty(a)
}
func (unauthorizingListAdmin) RemoveBlocklistTerm(_ context.Context, a domain.AdministratorID, _ string) error {
	return refuseEmpty(a)
}

func refuseEmpty(a domain.AdministratorID) error {
	if a == "" {
		return domain.ErrUnauthorized
	}
	return nil
}

// TestAdminListEditCoercesNilIdentifier pins the defensive coercion: a handler
// built with a nil AdminIdentifier -- a caller contract violation -- must not
// panic on the authorization path. It is coerced to the deny-all stand-in, so
// the request takes the SAME uniform 403 an unknown administrator gets, with no
// new status introduced.
func TestAdminListEditCoercesNilIdentifier(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.DiscardHandler)
	h := addAllowlistEntryHandler(unauthorizingListAdmin{}, nil, logger)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/reserved/allowlist",
		strings.NewReader(`{"entry":"admin"}`))
	rec := httptest.NewRecorder()
	// Must not panic on the nil interface.
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("edit with a nil identifier = %d, want a uniform 403", rec.Code)
	}
}
