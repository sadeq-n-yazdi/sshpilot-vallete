package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/counter"
)

// recordingStore is a counter.Store that counts Increment calls while
// delegating behavior to a real MemoryStore, so a test can prove which store a
// handler actually reached.
type recordingStore struct {
	mu    sync.Mutex
	calls int
	inner counter.Store
}

func newRecordingStore(t *testing.T) *recordingStore {
	t.Helper()
	inner, err := counter.NewMemoryStore(time.Now)
	if err != nil {
		t.Fatalf("NewMemoryStore: %v", err)
	}
	return &recordingStore{inner: inner}
}

func (r *recordingStore) Increment(ctx context.Context, key string, delta int64, ttl time.Duration) (counter.Count, error) {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	return r.inner.Increment(ctx, key, delta, ttl)
}

func (r *recordingStore) Get(ctx context.Context, key string) (counter.Count, error) {
	return r.inner.Get(ctx, key)
}

func (r *recordingStore) Delete(ctx context.Context, key string) error {
	return r.inner.Delete(ctx, key)
}

func (r *recordingStore) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// TestWithCounterStoreIsUsed proves the injected store -- not a freshly built
// in-process one -- backs the rate-limit tiers: a request to a rate-limited
// route increments the store the option supplied.
func TestWithCounterStoreIsUsed(t *testing.T) {
	t.Parallel()
	rec := newRecordingStore(t)
	cfg := config.Default() // rate limiting enabled; publish tier keyed per IP.

	h := NewHandler(&cfg, nil, okPinger{}, stubPublisher{body: []byte("ssh-ed25519 AAAA x\n")},
		WithCounterStore(rec))

	req := httptest.NewRequest(http.MethodGet, "/handle/set", nil)
	req.RemoteAddr = "203.0.113.9:5555"
	h.ServeHTTP(httptest.NewRecorder(), req)

	if rec.count() == 0 {
		t.Fatal("injected counter store was not used by the rate-limit middleware")
	}
}

// TestWithCounterStoreNilFallsBack proves a nil injected store is treated as
// "not supplied" rather than becoming the reason rate limiting vanishes: the
// handler still builds and serves.
func TestWithCounterStoreNilFallsBack(t *testing.T) {
	t.Parallel()
	cfg := config.Default()

	h := NewHandler(&cfg, nil, okPinger{}, stubPublisher{body: []byte("ssh-ed25519 AAAA x\n")},
		WithCounterStore(nil))

	req := httptest.NewRequest(http.MethodGet, "/handle/set", nil)
	req.RemoteAddr = "203.0.113.9:5555"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (a nil store must fall back, not break serving)", w.Code)
	}
}
