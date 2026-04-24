package stego

import (
	"math/rand"
	"testing"
)

// --- calculateEntropy ---

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantMin float64
		wantMax float64
	}{
		{
			name:    "empty",
			data:    []byte{},
			wantMin: 0,
			wantMax: 0,
		},
		{
			name:    "single byte repeated",
			data:    bytes256(0xAA, 256),
			wantMin: 0,
			wantMax: 0,
		},
		{
			name:    "two values equal probability",
			data:    alternating(256),
			wantMin: 0.99,
			wantMax: 1.01,
		},
		{
			name:    "all 256 values uniform",
			data:    allBytes(),
			wantMin: 7.9,
			wantMax: 8.1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateEntropy(tt.data)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("calculateEntropy() = %f, want [%f, %f]", got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

// --- hasHighEntropyRegions ---

func TestHasHighEntropyRegions(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{
			name: "empty",
			data: []byte{},
			want: false,
		},
		{
			name: "low entropy repeated pattern",
			data: bytes256(0xAB, 4096),
			want: false,
		},
		{
			name: "high entropy random data",
			data: randomBytes(8192),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasHighEntropyRegions(tt.data)
			if got != tt.want {
				t.Errorf("hasHighEntropyRegions() = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- chiSquareTest ---

func TestChiSquareTest(t *testing.T) {
	t.Run("empty histogram", func(t *testing.T) {
		cs, p := chiSquareTest(map[uint32]int{}, 0)
		if cs != 0 || p != 1 {
			t.Errorf("empty: got (%.2f, %.2f), want (0, 1)", cs, p)
		}
	})

	t.Run("uniform histogram high p-value", func(t *testing.T) {
		// 256 buckets, 256 observations each → perfectly uniform → p should be high
		hist := make(map[uint32]int)
		for i := uint32(0); i < 256; i++ {
			hist[i] = 256
		}
		total := 256 * 256
		_, p := chiSquareTest(hist, total)
		if p < 0.05 {
			t.Errorf("uniform histogram: p-value = %f, want >= 0.05", p)
		}
	})

	t.Run("non-uniform histogram low p-value", func(t *testing.T) {
		// All observations in one bucket → highly non-uniform → p should be very low
		hist := make(map[uint32]int)
		for i := uint32(0); i < 256; i++ {
			hist[i] = 0
		}
		hist[0] = 65536
		total := 65536
		_, p := chiSquareTest(hist, total)
		if p >= 0.05 {
			t.Errorf("non-uniform histogram: p-value = %f, want < 0.05", p)
		}
	})
}

// --- helpers ---

func bytes256(val byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = val
	}
	return b
}

func alternating(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		if i%2 == 0 {
			b[i] = 0x00
		} else {
			b[i] = 0xFF
		}
	}
	return b
}

func allBytes() []byte {
	// 256 bytes, one of each value
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func randomBytes(n int) []byte {
	r := rand.New(rand.NewSource(42))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Intn(256))
	}
	return b
}
