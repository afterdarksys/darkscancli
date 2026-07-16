package main

import (
	"bytes"
	"context"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMutationStrategiesDoNotPanic(t *testing.T) {
	inputs := [][]byte{
		{},
		{0x41},
		[]byte("hello world"),
		bytes.Repeat([]byte{0xAA}, 64),
	}

	// Per-strategy expected length relationship between input and output.
	// Fixed-size mutators (bit/byte-level rewrites) must preserve length
	// exactly. block-insert/block-duplicate only ever grow or hold steady.
	// block-delete only ever shrinks or holds steady — including all the
	// way down to zero when it deletes the entirety of a tiny input, which
	// is correct AFL-style behavior, not a bug. havoc stacks arbitrary
	// mutators so any non-negative length is valid.
	checkLen := map[string]func(inLen, outLen int) bool{
		"bitflip":         func(inLen, outLen int) bool { return outLen == inLen },
		"multi-bitflip":   func(inLen, outLen int) bool { return outLen == inLen },
		"byteflip":        func(inLen, outLen int) bool { return outLen == inLen },
		"byte-arith":      func(inLen, outLen int) bool { return outLen == inLen },
		"interesting":     func(inLen, outLen int) bool { return outLen == inLen },
		"random-byte":     func(inLen, outLen int) bool { return outLen == inLen },
		"block-insert":    func(inLen, outLen int) bool { return outLen >= inLen },
		"block-duplicate": func(inLen, outLen int) bool { return outLen >= inLen },
		"block-delete":    func(inLen, outLen int) bool { return outLen <= inLen },
		"havoc":           func(inLen, outLen int) bool { return outLen >= 0 },
	}

	for _, strat := range mutationStrategies {
		strat := strat
		want, ok := checkLen[strat.name]
		if !ok {
			t.Fatalf("test does not know the length invariant for mutation %q; add one", strat.name)
		}
		for _, in := range inputs {
			in := in
			t.Run(strat.name, func(t *testing.T) {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("mutation %q panicked on input len %d: %v", strat.name, len(in), r)
					}
				}()

				rng := rand.New(rand.NewSource(1))
				out := strat.fn(in, rng)

				if out == nil {
					t.Fatalf("mutation %q returned nil for input len %d", strat.name, len(in))
				}
				if !want(len(in), len(out)) {
					t.Fatalf("mutation %q: input len %d produced unexpected output len %d", strat.name, len(in), len(out))
				}
				if len(out) > len(in)*4+64 {
					t.Fatalf("mutation %q grew input of len %d to unreasonable len %d", strat.name, len(in), len(out))
				}
			})
		}
	}
}

func TestSplitCommand(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"/bin/sh -c 'exit 0'", []string{"/bin/sh", "-c", "exit 0"}},
		{"/usr/bin/prog @@", []string{"/usr/bin/prog", "@@"}},
		{`prog "arg one" arg2`, []string{"prog", "arg one", "arg2"}},
	}

	for _, c := range cases {
		got := splitCommand(c.in)
		if len(got) != len(c.want) {
			t.Fatalf("splitCommand(%q) = %v, want %v", c.in, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("splitCommand(%q) = %v, want %v", c.in, got, c.want)
			}
		}
	}
}

func TestFuzzEngineNoOpTargetHasNoCrashes(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available on this system")
	}

	dir := t.TempDir()
	seedPath := filepath.Join(dir, "seed.bin")
	if err := os.WriteFile(seedPath, []byte("AAAA"), 0o644); err != nil {
		t.Fatalf("failed to write seed: %v", err)
	}

	opts := fuzzOptions{
		target:     `/bin/sh -c "exit 0"`,
		seedPath:   seedPath,
		iterations: 20,
		timeout:    2 * time.Second,
		outDir:     filepath.Join(dir, "findings"),
		rngSeed:    42,
		workers:    2,
		jsonOutput: true,
	}

	summary, err := runFuzzEngine(context.Background(), opts, io.Discard)
	if err != nil {
		t.Fatalf("runFuzzEngine returned error: %v", err)
	}

	if summary.Executed != int64(opts.iterations) {
		t.Fatalf("expected %d executions, got %d", opts.iterations, summary.Executed)
	}
	if summary.Crashes != 0 {
		t.Fatalf("expected 0 crashes for no-op target, got %d", summary.Crashes)
	}
	if summary.Hangs != 0 {
		t.Fatalf("expected 0 hangs for no-op target, got %d", summary.Hangs)
	}
}

func TestFuzzEngineValidation(t *testing.T) {
	dir := t.TempDir()

	if _, err := runFuzzEngine(context.Background(), fuzzOptions{}, io.Discard); err == nil {
		t.Fatal("expected error for missing --target")
	}

	if _, err := runFuzzEngine(context.Background(), fuzzOptions{target: "/bin/sh"}, io.Discard); err == nil {
		t.Fatal("expected error for missing seed/seed-dir")
	}

	seedPath := filepath.Join(dir, "seed.bin")
	if err := os.WriteFile(seedPath, []byte("x"), 0o644); err != nil {
		t.Fatalf("failed to write seed: %v", err)
	}
	opts := fuzzOptions{
		target:     "/no/such/binary-xyz",
		seedPath:   seedPath,
		iterations: 1,
		timeout:    time.Second,
		outDir:     filepath.Join(dir, "findings"),
		workers:    1,
	}
	if _, err := runFuzzEngine(context.Background(), opts, io.Discard); err == nil {
		t.Fatal("expected error for non-existent target binary")
	}
}
