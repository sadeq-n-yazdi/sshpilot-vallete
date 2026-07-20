package postgres

import (
	"database/sql"
	"strings"
	"testing"
	"time"
)

// These tests are pure encoding checks and need no database, so they run even
// when VALLET_TEST_POSTGRES_DSN is unset.

func TestEncTimeIsFixedWidthUTC(t *testing.T) {
	t.Parallel()
	zone := time.FixedZone("UTC-5", -5*60*60)
	local := testClock.In(zone)

	got := encTime(local)
	if !strings.HasSuffix(got, "Z") {
		t.Errorf("encTime(%v) = %q, want a UTC value ending in Z", local, got)
	}
	if got != encTime(testClock) {
		t.Errorf("encTime is zone-dependent: %q vs %q", got, encTime(testClock))
	}
	// Every encoding must be the same width regardless of the instant or the
	// zone it arrived in; that is what makes the lexical ordering below sound.
	// The width is that of a rendered UTC value ("...Z"), not of the layout
	// string, whose "Z07:00" placeholder is wider than the "Z" it produces.
	const wantWidth = len("2006-01-02T15:04:05.000000000Z")
	for _, tm := range []time.Time{testClock, local, time.Unix(0, 0), testClock.Add(time.Nanosecond)} {
		if enc := encTime(tm); len(enc) != wantWidth {
			t.Errorf("encTime(%v) width = %d, want the fixed %d", tm, len(enc), wantWidth)
		}
	}
}

// TestEncTimeLexicalOrderMatchesChronological pins the invariant the quarantine
// sweep's "<=" predicate depends on: because every encoding is fixed-width UTC,
// comparing the stored text byte-wise orders the instants correctly.
func TestEncTimeLexicalOrderMatchesChronological(t *testing.T) {
	t.Parallel()
	instants := []time.Time{
		testClock.Add(-48 * time.Hour),
		testClock.Add(-time.Nanosecond),
		testClock,
		testClock.Add(time.Nanosecond),
		testClock.Add(72 * time.Hour),
	}
	for i := 1; i < len(instants); i++ {
		prev, cur := encTime(instants[i-1]), encTime(instants[i])
		if prev >= cur {
			t.Errorf("lexical order broken: %q not < %q", prev, cur)
		}
	}
}

func TestEncDecTimeRoundTrip(t *testing.T) {
	t.Parallel()
	want := testClock.Add(1234 * time.Nanosecond)

	got, err := decTime(encTime(want))
	if err != nil {
		t.Fatalf("decTime: %v", err)
	}
	if !got.Equal(want) {
		t.Errorf("round-trip = %v, want %v", got, want)
	}
	if got.Location() != time.UTC {
		t.Errorf("round-trip location = %v, want UTC", got.Location())
	}
}

func TestDecTimeRejectsMalformed(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"", "not-a-time", "2026-07-19 10:00:00"} {
		if _, err := decTime(s); err == nil {
			t.Errorf("decTime(%q) returned no error", s)
		}
	}
}

// TestNullTimeHelpers pins the nil/NULL correspondence in both directions.
func TestNullTimeHelpers(t *testing.T) {
	t.Parallel()

	if got := encNullTime(nil); got != nil {
		t.Errorf("encNullTime(nil) = %v, want nil (SQL NULL)", got)
	}
	if got := encNullTime(&testClock); got != encTime(testClock) {
		t.Errorf("encNullTime(&t) = %v, want %q", got, encTime(testClock))
	}

	got, err := decNullTime(sql.NullString{})
	if err != nil || got != nil {
		t.Errorf("decNullTime(NULL) = (%v, %v), want (nil, nil)", got, err)
	}
	got, err = decNullTime(sql.NullString{String: encTime(testClock), Valid: true})
	if err != nil {
		t.Fatalf("decNullTime: %v", err)
	}
	if got == nil || !got.Equal(testClock) {
		t.Errorf("decNullTime = %v, want %v", got, testClock)
	}
	if _, err := decNullTime(sql.NullString{String: "garbage", Valid: true}); err == nil {
		t.Error("decNullTime(garbage) returned no error")
	}
}
