package store

import "testing"

func TestCleanPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want string
		ok       bool
	}{{"/a/b", "a/b", true}, {"a//b", "a/b", true}, {"", "", true}, {"../etc/passwd", "", false}, {"a/../b", "", false}, {"bad\x00name", "", false}}
	for _, tt := range tests {
		got, err := CleanPath(tt.in)
		if tt.ok && err != nil {
			t.Errorf("CleanPath(%q): %v", tt.in, err)
		}
		if !tt.ok && err == nil {
			t.Errorf("CleanPath(%q) unexpectedly succeeded", tt.in)
		}
		if tt.ok && got != tt.want {
			t.Errorf("CleanPath(%q)=%q want %q", tt.in, got, tt.want)
		}
	}
}
