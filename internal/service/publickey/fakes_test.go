package publickey_test

// This file holds the environment and the in-memory ports the tests in this
// package drive. They are kept separate from the assertions so a reader can see
// at a glance what is being faked and what is real.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/publickey"
)

// --- helpers ---

var (
	errSinkDown = errors.New("audit sink down")
	fixedNow    = time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
)

type env struct {
	svc     *publickey.Service
	keys    *memKeyRepo
	devices *memDeviceRepo
	auditor *memAuditor
	now     time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()

	e := &env{
		keys:    &memKeyRepo{rows: map[domain.PublicKeyID]*domain.PublicKey{}},
		devices: &memDeviceRepo{rows: map[domain.DeviceID]*domain.Device{}},
		auditor: &memAuditor{},
		now:     fixedNow,
	}
	svc, err := publickey.New(e.keys, e.devices, e.auditor,
		publickey.WithClock(func() time.Time { return e.now }))
	if err != nil {
		t.Fatalf("publickey.New: %v", err)
	}
	e.svc = svc
	return e
}

func (e *env) seedDevice(owner domain.OwnerID, id domain.DeviceID) *domain.Device {
	d := &domain.Device{
		ID: id, OwnerID: owner, Name: "seed", Status: domain.DeviceStatusActive,
		CreatedAt: e.now, UpdatedAt: e.now,
	}
	e.devices.rows[id] = d
	return d
}

func countAction(events []audit.Event, action domain.AuditAction) int {
	n := 0
	for _, ev := range events {
		if ev.Action == action {
			n++
		}
	}
	return n
}

func values(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

func ed25519Line(t *testing.T, comment string) string {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	line := strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(sshPub)), "\n")
	if comment != "" {
		line += " " + comment
	}
	return line
}

func privateKeyPEM(t *testing.T) string {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	return string(pem.EncodeToMemory(block))
}

// memAuditor records emitted events and can be made to fail.
type memAuditor struct {
	events []audit.Event
	err    error
}

func (a *memAuditor) Emit(_ context.Context, ev audit.Event) error {
	if a.err != nil {
		return a.err
	}
	a.events = append(a.events, ev)
	return nil
}

type memSink struct{ records []*domain.AuditRecord }

func (s *memSink) Append(_ context.Context, rec *domain.AuditRecord) error {
	s.records = append(s.records, rec)
	return nil
}

// memKeyRepo is an in-memory PublicKeyRepository enforcing the owner scoping
// and per-owner fingerprint uniqueness the real adapters promise. It does NOT
// collapse "already revoked" into not-found: that is the service's job, and a
// fake that did it would make the service's own logic untestable.
type memKeyRepo struct {
	rows  map[domain.PublicKeyID]*domain.PublicKey
	order []domain.PublicKeyID
}

func (r *memKeyRepo) Create(_ context.Context, k *domain.PublicKey) error {
	for _, existing := range r.rows {
		if existing.OwnerID == k.OwnerID && existing.Fingerprint == k.Fingerprint {
			return domain.ErrConflict
		}
	}
	clone := *k
	r.rows[k.ID] = &clone
	r.order = append(r.order, k.ID)
	return nil
}

func (r *memKeyRepo) Get(_ context.Context, ownerID domain.OwnerID, id domain.PublicKeyID) (*domain.PublicKey, error) {
	k, ok := r.rows[id]
	if !ok || k.OwnerID != ownerID {
		return nil, domain.ErrNotFound
	}
	clone := *k
	return &clone, nil
}

func (r *memKeyRepo) ListByOwner(_ context.Context, ownerID domain.OwnerID) ([]domain.PublicKey, error) {
	var out []domain.PublicKey
	for _, id := range r.order {
		if k := r.rows[id]; k != nil && k.OwnerID == ownerID {
			out = append(out, *k)
		}
	}
	return out, nil
}

func (r *memKeyRepo) ListByDevice(_ context.Context, ownerID domain.OwnerID, deviceID domain.DeviceID) ([]domain.PublicKey, error) {
	var out []domain.PublicKey
	for _, id := range r.order {
		if k := r.rows[id]; k != nil && k.OwnerID == ownerID && k.DeviceID == deviceID {
			out = append(out, *k)
		}
	}
	return out, nil
}

func (r *memKeyRepo) GetByFingerprint(_ context.Context, ownerID domain.OwnerID, fingerprint string) (*domain.PublicKey, error) {
	for _, k := range r.rows {
		if k.OwnerID == ownerID && k.Fingerprint == fingerprint {
			clone := *k
			return &clone, nil
		}
	}
	return nil, domain.ErrNotFound
}

func (r *memKeyRepo) Revoke(_ context.Context, ownerID domain.OwnerID, id domain.PublicKeyID, now time.Time) error {
	k, ok := r.rows[id]
	if !ok || k.OwnerID != ownerID {
		return domain.ErrNotFound
	}
	k.Status, k.UpdatedAt, k.RevokedAt = domain.KeyStatusRevoked, now, &now
	return nil
}

func (r *memKeyRepo) RevokeByDevice(_ context.Context, ownerID domain.OwnerID, deviceID domain.DeviceID, now time.Time) (int64, error) {
	var n int64
	for _, k := range r.rows {
		if k.OwnerID == ownerID && k.DeviceID == deviceID && k.Status == domain.KeyStatusActive {
			k.Status, k.UpdatedAt, k.RevokedAt = domain.KeyStatusRevoked, now, &now
			n++
		}
	}
	return n, nil
}

func (r *memKeyRepo) ListActiveByKeySet(context.Context, domain.OwnerID, domain.KeySetID) ([]domain.PublicKey, error) {
	return nil, nil
}

// memDeviceRepo is an in-memory DeviceRepository enforcing the owner scoping
// the real adapters promise.
type memDeviceRepo struct {
	rows map[domain.DeviceID]*domain.Device
}

func (r *memDeviceRepo) Create(_ context.Context, d *domain.Device) error {
	clone := *d
	r.rows[d.ID] = &clone
	return nil
}

func (r *memDeviceRepo) Get(_ context.Context, ownerID domain.OwnerID, id domain.DeviceID) (*domain.Device, error) {
	d, ok := r.rows[id]
	if !ok || d.OwnerID != ownerID {
		return nil, domain.ErrNotFound
	}
	clone := *d
	return &clone, nil
}

func (r *memDeviceRepo) ListByOwner(_ context.Context, ownerID domain.OwnerID) ([]domain.Device, error) {
	var out []domain.Device
	for _, d := range r.rows {
		if d.OwnerID == ownerID {
			out = append(out, *d)
		}
	}
	return out, nil
}

func (r *memDeviceRepo) Rename(_ context.Context, ownerID domain.OwnerID, id domain.DeviceID, name string, now time.Time) error {
	d, ok := r.rows[id]
	if !ok || d.OwnerID != ownerID {
		return domain.ErrNotFound
	}
	d.Name, d.UpdatedAt = name, now
	return nil
}

func (r *memDeviceRepo) Revoke(_ context.Context, ownerID domain.OwnerID, id domain.DeviceID, now time.Time) error {
	d, ok := r.rows[id]
	if !ok || d.OwnerID != ownerID {
		return domain.ErrNotFound
	}
	d.Status, d.UpdatedAt, d.RevokedAt = domain.DeviceStatusRevoked, now, &now
	return nil
}
