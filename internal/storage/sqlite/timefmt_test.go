package sqlite

import (
	"database/sql"
	"sort"
	"testing"
	"time"
)

func TestEncDecTimeRoundTrip(t *testing.T) {
	t.Parallel()
	want := time.Date(2026, 7, 19, 12, 34, 56, 123456789, time.UTC)

	s := encTime(want)
	got, err := decTime(s)
	if err != nil {
		t.Fatalf("decTime(%q): %v", s, err)
	}
	if !got.Equal(want) {
		t.Errorf("round-trip = %v, want %v (sub-second precision lost)", got, want)
	}
	if got.Location() != time.UTC {
		t.Errorf("decoded location = %v, want UTC", got.Location())
	}
}

func TestEncTimeForcesUTC(t *testing.T) {
	t.Parallel()
	// 12:00 in a +05:00 zone is 07:00 UTC; the encoded form must be the UTC
	// instant and must end in "Z" (never a numeric offset), which is what keeps
	// the fixed-width lexical ordering invariant intact.
	zone := time.FixedZone("plus5", 5*60*60)
	local := time.Date(2026, 7, 19, 12, 0, 0, 0, zone)

	s := encTime(local)
	if s[len(s)-1] != 'Z' {
		t.Errorf("encoded %q does not end in Z", s)
	}

	got, err := decTime(s)
	if err != nil {
		t.Fatalf("decTime: %v", err)
	}
	if !got.Equal(local) {
		t.Errorf("decoded instant = %v, want %v", got, local)
	}
	if h := got.Hour(); h != 7 {
		t.Errorf("UTC hour = %d, want 7 (zone was not normalized)", h)
	}
}

func TestEncTimeFixedWidthAndOrdering(t *testing.T) {
	t.Parallel()
	times := []time.Time{
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 7, 19, 12, 34, 56, 1, time.UTC),
		time.Date(2026, 7, 19, 12, 34, 56, 2, time.UTC),
		time.Date(2030, 12, 31, 23, 59, 59, 999999999, time.UTC),
	}

	encoded := make([]string, len(times))
	width := len(encTime(times[0]))
	for i, tm := range times {
		encoded[i] = encTime(tm)
		if len(encoded[i]) != width {
			t.Errorf("encoded width = %d for %v, want fixed %d", len(encoded[i]), tm, width)
		}
	}

	// Encoded strings, sorted lexically, must remain in chronological order.
	shuffled := append([]string(nil), encoded...)
	sort.Strings(shuffled)
	for i := range encoded {
		if shuffled[i] != encoded[i] {
			t.Fatalf("lexical order != chronological order at %d: %q vs %q",
				i, shuffled[i], encoded[i])
		}
	}
}

func TestEncNullTime(t *testing.T) {
	t.Parallel()
	if v := encNullTime(nil); v != nil {
		t.Errorf("encNullTime(nil) = %#v, want untyped nil", v)
	}

	tm := time.Date(2026, 7, 19, 1, 2, 3, 0, time.UTC)
	v := encNullTime(&tm)
	s, ok := v.(string)
	if !ok {
		t.Fatalf("encNullTime(&t) = %T, want string", v)
	}
	if s != encTime(tm) {
		t.Errorf("encNullTime string = %q, want %q", s, encTime(tm))
	}
}

func TestDecNullTime(t *testing.T) {
	t.Parallel()
	got, err := decNullTime(sql.NullString{Valid: false})
	if err != nil {
		t.Fatalf("decNullTime(NULL): %v", err)
	}
	if got != nil {
		t.Errorf("decNullTime(NULL) = %v, want nil", got)
	}

	want := time.Date(2026, 7, 19, 1, 2, 3, 456000000, time.UTC)
	got, err = decNullTime(sql.NullString{String: encTime(want), Valid: true})
	if err != nil {
		t.Fatalf("decNullTime(valid): %v", err)
	}
	if got == nil || !got.Equal(want) {
		t.Errorf("decNullTime(valid) = %v, want %v", got, want)
	}
}

func TestDecTimeInvalid(t *testing.T) {
	t.Parallel()
	if _, err := decTime("not-a-timestamp"); err == nil {
		t.Error("decTime(invalid) = nil error, want error")
	}
	if _, err := decNullTime(sql.NullString{String: "bad", Valid: true}); err == nil {
		t.Error("decNullTime(invalid) = nil error, want error")
	}
}
