package version

import "testing"

func TestString(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: "returns default development version",
			want: "0.0.0-dev",
		},
		{
			name: "matches exported Version constant",
			want: Version,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}
