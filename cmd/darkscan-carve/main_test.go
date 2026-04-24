package main

import (
	"testing"

	"github.com/afterdarksys/darkscan/pkg/carving"
)

func TestFilterSignatures(t *testing.T) {
	// Ensure there are signatures to work with
	if len(carving.Signatures) == 0 {
		t.Skip("no signatures defined")
	}

	t.Run("empty types returns nothing", func(t *testing.T) {
		got := filterSignatures([]string{})
		if len(got) != 0 {
			t.Errorf("expected 0 results for empty types, got %d", len(got))
		}
	})

	t.Run("unknown type returns nothing", func(t *testing.T) {
		got := filterSignatures([]string{"zzz_nonexistent_type"})
		if len(got) != 0 {
			t.Errorf("expected 0 results for unknown type, got %d", len(got))
		}
	})

	t.Run("match by extension", func(t *testing.T) {
		// Pick the extension of the first signature
		first := carving.Signatures[0]
		got := filterSignatures([]string{first.Extension})
		if len(got) == 0 {
			t.Errorf("expected at least one result for extension %q", first.Extension)
		}
		for _, sig := range got {
			if sig.Extension != first.Extension && sig.Category != first.Extension {
				t.Errorf("unexpected signature in result: ext=%q cat=%q", sig.Extension, sig.Category)
			}
		}
	})

	t.Run("match by category", func(t *testing.T) {
		first := carving.Signatures[0]
		got := filterSignatures([]string{first.Category})
		if len(got) == 0 {
			t.Errorf("expected at least one result for category %q", first.Category)
		}
		for _, sig := range got {
			if sig.Category != first.Category && sig.Extension != first.Category {
				t.Errorf("unexpected category in result: %q", sig.Category)
			}
		}
	})

	t.Run("case insensitive", func(t *testing.T) {
		first := carving.Signatures[0]
		lower := filterSignatures([]string{first.Extension})
		upper := filterSignatures([]string{toUpper(first.Extension)})
		if len(lower) != len(upper) {
			t.Errorf("case sensitivity issue: lower=%d upper=%d", len(lower), len(upper))
		}
	})
}

func toUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}
