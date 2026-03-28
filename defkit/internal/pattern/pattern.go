package pattern

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// Pattern represents an extracted binary pattern
type Pattern struct {
	Offset      int64  `json:"offset"`
	HexPattern  string `json:"hex_pattern"`
	WildcardHex string `json:"wildcard_hex,omitempty"`
	Length      int    `json:"length"`
	Entropy     float64 `json:"entropy,omitempty"`
}

// String represents an extracted string
type String struct {
	Offset int64  `json:"offset"`
	Value  string `json:"value"`
	Type   string `json:"type"` // ascii, unicode, url, ip, domain
}

// ExtractStrings extracts printable strings from binary data
func ExtractStrings(data []byte, minLength int) []String {
	if minLength < 4 {
		minLength = 4
	}

	var strings []String
	var current []byte
	var offset int64

	for i := 0; i < len(data); i++ {
		if isPrintable(data[i]) {
			if len(current) == 0 {
				offset = int64(i)
			}
			current = append(current, data[i])
		} else {
			if len(current) >= minLength {
				str := String{
					Offset: offset,
					Value:  string(current),
					Type:   classifyString(string(current)),
				}
				strings = append(strings, str)
			}
			current = nil
		}
	}

	// Handle final string
	if len(current) >= minLength {
		str := String{
			Offset: offset,
			Value:  string(current),
			Type:   classifyString(string(current)),
		}
		strings = append(strings, str)
	}

	// Also extract Unicode strings
	unicodeStrings := extractUnicodeStrings(data, minLength)
	strings = append(strings, unicodeStrings...)

	return strings
}

// extractUnicodeStrings extracts UTF-16 LE strings
func extractUnicodeStrings(data []byte, minLength int) []String {
	var strings []String
	var current []rune
	var offset int64

	for i := 0; i < len(data)-1; i += 2 {
		// UTF-16 LE: low byte first
		r := rune(data[i]) | rune(data[i+1])<<8

		if r > 0 && r < 128 && isPrintable(byte(r)) {
			if len(current) == 0 {
				offset = int64(i)
			}
			current = append(current, r)
		} else {
			if len(current) >= minLength {
				str := String{
					Offset: offset,
					Value:  string(current),
					Type:   "unicode",
				}
				strings = append(strings, str)
			}
			current = nil
		}
	}

	if len(current) >= minLength {
		str := String{
			Offset: offset,
			Value:  string(current),
			Type:   "unicode",
		}
		strings = append(strings, str)
	}

	return strings
}

func isPrintable(b byte) bool {
	return b >= 32 && b <= 126
}

func classifyString(s string) string {
	// URL pattern
	if matched, _ := regexp.MatchString(`^https?://`, s); matched {
		return "url"
	}

	// IP address pattern
	if matched, _ := regexp.MatchString(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`, s); matched {
		return "ip"
	}

	// Domain pattern
	if matched, _ := regexp.MatchString(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$`, s); matched {
		return "domain"
	}

	// File path
	if strings.Contains(s, "\\") || strings.Contains(s, "/") {
		return "path"
	}

	return "ascii"
}

// ExtractPatterns extracts binary patterns suitable for signatures
func ExtractPatterns(data []byte, minLength, maxLength int) []Pattern {
	if minLength < 4 {
		minLength = 4
	}
	if maxLength < minLength {
		maxLength = 64
	}

	var patterns []Pattern

	// Find sequences of non-zero bytes
	var current []byte
	var offset int64

	for i := 0; i < len(data); i++ {
		if data[i] != 0 {
			if len(current) == 0 {
				offset = int64(i)
			}
			current = append(current, data[i])

			if len(current) >= maxLength {
				pattern := createPattern(current, offset)
				patterns = append(patterns, pattern)
				current = nil
			}
		} else {
			if len(current) >= minLength {
				pattern := createPattern(current, offset)
				patterns = append(patterns, pattern)
			}
			current = nil
		}
	}

	if len(current) >= minLength {
		pattern := createPattern(current, offset)
		patterns = append(patterns, pattern)
	}

	return patterns
}

func createPattern(data []byte, offset int64) Pattern {
	hexStr := hex.EncodeToString(data)

	return Pattern{
		Offset:     offset,
		HexPattern: hexStr,
		Length:     len(data),
		Entropy:    calculateEntropy(data),
	}
}

// CreateWildcardPattern creates a pattern with wildcards for variable bytes
func CreateWildcardPattern(data []byte, wildcardPositions []int) string {
	var result strings.Builder

	for i := 0; i < len(data); i++ {
		isWildcard := false
		for _, pos := range wildcardPositions {
			if i == pos {
				isWildcard = true
				break
			}
		}

		if isWildcard {
			result.WriteString("??")
		} else {
			result.WriteString(fmt.Sprintf("%02x", data[i]))
		}
	}

	return result.String()
}

// calculateEntropy calculates Shannon entropy
func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	var entropy float64
	length := float64(len(data))

	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * (logBase2(p))
		}
	}

	return entropy
}

func logBase2(x float64) float64 {
	if x == 0 {
		return 0
	}
	return 0.6931471805599453 / (1.0 / x) // log2(x) approximation
}

// FindCommonSubsequence finds longest common subsequence in multiple samples
func FindCommonSubsequence(samples [][]byte, minLength int) []byte {
	if len(samples) < 2 {
		return nil
	}

	// Use first sample as reference
	reference := samples[0]

	for length := len(reference); length >= minLength; length-- {
		for offset := 0; offset <= len(reference)-length; offset++ {
			candidate := reference[offset : offset+length]

			// Check if this sequence exists in all samples
			foundInAll := true
			for i := 1; i < len(samples); i++ {
				if !bytes.Contains(samples[i], candidate) {
					foundInAll = false
					break
				}
			}

			if foundInAll {
				return candidate
			}
		}
	}

	return nil
}

// NormalizePattern removes common variable sections
func NormalizePattern(pattern string) string {
	// Remove timestamps, counters, random data
	normalized := pattern

	// Replace sequences of variable hex with wildcards
	re := regexp.MustCompile(`([0-9a-f]{2})\1{3,}`)
	normalized = re.ReplaceAllString(normalized, "????")

	return normalized
}

// SplitIntoChunks splits a hex pattern into chunks for signature generation
func SplitIntoChunks(hexPattern string, chunkSize int) []string {
	if chunkSize <= 0 {
		chunkSize = 32
	}

	var chunks []string
	for i := 0; i < len(hexPattern); i += chunkSize * 2 {
		end := i + chunkSize*2
		if end > len(hexPattern) {
			end = len(hexPattern)
		}
		chunks = append(chunks, hexPattern[i:end])
	}

	return chunks
}

// IsHighEntropySection checks if data is likely packed/encrypted
func IsHighEntropySection(data []byte) bool {
	return calculateEntropy(data) > 7.0
}
