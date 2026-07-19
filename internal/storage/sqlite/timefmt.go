package sqlite

import (
	"database/sql"
	"fmt"
	"time"
)

// timeLayout is a fixed-width UTC RFC3339 layout with nanosecond precision.
//
// Every encoded timestamp has exactly the same width and a trailing "Z", so a
// lexical (byte-wise) string comparison in SQL matches chronological order.
// This holds only because encTime forces UTC before formatting: a non-zero
// zone offset would render as "+hh:mm"/"-hh:mm" (six characters) instead of the
// single "Z", breaking both the fixed width and the ordering invariant.
const timeLayout = "2006-01-02T15:04:05.000000000Z07:00"

// encTime formats t as a fixed-width UTC RFC3339 string. t is converted to UTC
// first, so the result always ends in "Z" and sorts chronologically as text.
func encTime(t time.Time) string {
	return t.UTC().Format(timeLayout)
}

// decTime parses a string produced by encTime back into a time.Time in UTC.
func decTime(s string) (time.Time, error) {
	t, err := time.Parse(timeLayout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("sqlite: decode time: %w", err)
	}
	return t.UTC(), nil
}

// encNullTime encodes an optional timestamp for binding as a SQL argument. A
// nil pointer becomes an untyped nil (SQL NULL); a non-nil pointer becomes the
// fixed-width UTC string from encTime.
func encNullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return encTime(*t)
}

// decNullTime decodes an optional timestamp read from a nullable text column. A
// NULL column (ns.Valid == false) yields a nil pointer; otherwise the string is
// parsed with decTime.
func decNullTime(ns sql.NullString) (*time.Time, error) {
	if !ns.Valid {
		return nil, nil
	}
	t, err := decTime(ns.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
