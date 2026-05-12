package main

import "testing"

// TestSanitizeBrandColor: BRAND_COLOR env is inserted into <style>--brand: X;</style>.
// html/template CSS-context escaping does not stop CSS syntax injection, so the entry point must
// validate it. Invalid values silently fall back instead of crashing on bad admin input.
func TestSanitizeBrandColor(t *testing.T) {
	const fallback = "#2563eb"
	cases := []struct {
		in   string
		want string
	}{
		// Valid hex.
		{"#fff", "#fff"},
		{"#FFF", "#FFF"},
		{"#abcdef", "#abcdef"},
		{"#ABCDEF", "#ABCDEF"},
		{"#12345678", "#12345678"}, // #RRGGBBAA
		// Empty / whitespace -> fallback.
		{"", fallback},
		{"   ", fallback},
		// Invalid -> fallback.
		{"red", fallback},
		{"#xyz", fallback},
		{"#12", fallback},     // Wrong length.
		{"#12345", fallback},  // Wrong length.
		{"#123456789", fallback},
		// Attack payloads.
		{"red; } body { display: none } /*", fallback},
		{"#fff; background: url(http://evil)", fallback},
		{"javascript:alert(1)", fallback},
		{"#fff\n; @import url(x)", fallback},
	}
	for _, c := range cases {
		got := sanitizeBrandColor(c.in, fallback)
		if got != c.want {
			t.Errorf("sanitizeBrandColor(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
