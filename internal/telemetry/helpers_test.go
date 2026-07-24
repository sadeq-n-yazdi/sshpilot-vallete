package telemetry

import (
	"log/slog"
	"sort"
	"strconv"
)

// slogString builds the log-side attribute for the cross-sink agreement test.
func slogString(key, value string) slog.Attr { return slog.String(key, value) }

func itoa(i int) string { return strconv.Itoa(i) }

// keys returns a set's members in a stable order, for failure messages.
func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
