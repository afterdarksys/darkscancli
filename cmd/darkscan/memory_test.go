package main

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"short fully masked", "abcd", "****"},
		{"exactly eight masked", "abcdefgh", "********"},
		{"long revealed ends", "AKIAIOSFODNN7EXAMPLE", "AKIA************MPLE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redact(tt.in)
			if got != tt.want {
				t.Fatalf("redact(%q) = %q, want %q", tt.in, got, tt.want)
			}
			// Never leak the full secret for anything longer than 8 chars.
			if len(tt.in) > 8 && got == tt.in {
				t.Fatalf("redact(%q) leaked the full value", tt.in)
			}
			if strings.Contains(got, tt.in) && len(tt.in) > 8 {
				t.Fatalf("redact(%q) contains full value %q", tt.in, tt.in)
			}
		})
	}
}

func TestEntropy(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantMin float64
		wantMax float64
	}{
		{"empty", "", 0, 0},
		{"single repeated byte", "aaaaaaaa", 0, 0.0001},
		{"two symbols even", "abababab", 0.99, 1.01},
		{"high entropy token", "aB3xZ9qLmN7pW2kR", 3.0, 4.01},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := entropy(tt.in)
			if got < tt.wantMin || got > tt.wantMax {
				t.Fatalf("entropy(%q) = %.4f, want in [%.4f, %.4f]", tt.in, got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestDetectorMatch(t *testing.T) {
	// In-memory buffer with several planted secrets embedded in noise.
	buf := []byte("noise\x00\x01AKIAIOSFODNN7EXAMPLE more junk " +
		"ghp_012345678901234567890123456789012345 tail " +
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123-_ end " +
		"postgres://user:s3cretpw@db.example.com:5432/app trailing\x00")

	agg := make(map[string]*memoryFinding)
	var order []string
	dets := activeDetectors(nil)
	for _, es := range extractStrings(buf, 0, 6, 0) {
		scanString(es, dets, false, 4.0, 16, agg, &order)
	}

	found := make(map[string]bool)
	for _, key := range order {
		found[agg[key].Type] = true
	}

	for _, want := range []string{"aws_access_key_id", "github_token", "jwt", "db_connection_string"} {
		if !found[want] {
			t.Errorf("expected detector %q to match, but it did not (found: %v)", want, found)
		}
	}

	// Ensure the AWS key finding is redacted, never the raw secret.
	for _, key := range order {
		f := agg[key]
		if f.Type == "aws_access_key_id" {
			if f.Preview == "AKIAIOSFODNN7EXAMPLE" {
				t.Fatalf("finding leaked full AWS key in preview")
			}
			if !strings.Contains(f.Preview, "*") {
				t.Fatalf("expected redacted preview, got %q", f.Preview)
			}
		}
	}
}
