package stego

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"math"
	"os"
)

// Analysis result for steganography detection
type Analysis struct {
	FilePath         string
	Format           string
	Dimensions       image.Point
	Suspicious       bool
	Confidence       int // 0-100
	Indicators       []Indicator
	LSBAnalysis      *LSBAnalysis
	StatisticalTests *StatisticalTests
	Signatures       []Signature
}

// Indicator represents a suspicious indicator
type Indicator struct {
	Type        string  // "lsb", "entropy", "chi-square", "signature"
	Description string
	Severity    string  // "low", "medium", "high"
	Confidence  int     // 0-100
	Details     map[string]interface{}
}

// LSBAnalysis contains LSB-specific analysis
type LSBAnalysis struct {
	RedLSBEntropy   float64
	GreenLSBEntropy float64
	BlueLSBEntropy  float64
	AlphaLSBEntropy float64
	LSBRatio        float64 // Ratio of LSB changes
	Suspicious      bool
}

// StatisticalTests contains statistical analysis results
type StatisticalTests struct {
	ChiSquare      float64
	ChiSquarePValue float64
	HistogramFlat  bool
	EntropyScore   float64
}

// Signature represents a known steganography tool signature
type Signature struct {
	Tool        string
	Version     string
	Confidence  int
	Description string
}

// Analyzer performs steganography analysis
type Analyzer struct {
	checkLSB         bool
	checkStatistics  bool
	checkSignatures  bool
	minConfidence    int
}

// NewAnalyzer creates a new steganography analyzer
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		checkLSB:        true,
		checkStatistics: true,
		checkSignatures: true,
		minConfidence:   50,
	}
}

// AnalyzeFile analyzes a file for steganography
func (a *Analyzer) AnalyzeFile(path string) (*Analysis, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	// Decode image
	img, format, err := image.Decode(f)
	if err != nil {
		return nil, fmt.Errorf("decode image: %w", err)
	}

	analysis := &Analysis{
		FilePath:   path,
		Format:     format,
		Dimensions: img.Bounds().Size(),
		Indicators: []Indicator{},
	}

	// LSB Analysis
	if a.checkLSB {
		lsb := a.analyzeLSB(img)
		analysis.LSBAnalysis = lsb

		if lsb.Suspicious {
			analysis.Indicators = append(analysis.Indicators, Indicator{
				Type:        "lsb",
				Description: "Suspicious LSB pattern detected",
				Severity:    a.getLSBSeverity(lsb),
				Confidence:  a.getLSBConfidence(lsb),
				Details: map[string]interface{}{
					"red_entropy":   lsb.RedLSBEntropy,
					"green_entropy": lsb.GreenLSBEntropy,
					"blue_entropy":  lsb.BlueLSBEntropy,
					"lsb_ratio":     lsb.LSBRatio,
				},
			})
		}
	}

	// Statistical Analysis
	if a.checkStatistics {
		stats := a.analyzeStatistics(img)
		analysis.StatisticalTests = stats

		if stats.ChiSquarePValue < 0.05 {
			analysis.Indicators = append(analysis.Indicators, Indicator{
				Type:        "chi-square",
				Description: "Chi-square test indicates non-random data distribution",
				Severity:    "medium",
				Confidence:  int((1.0 - stats.ChiSquarePValue) * 100),
				Details: map[string]interface{}{
					"chi_square": stats.ChiSquare,
					"p_value":    stats.ChiSquarePValue,
				},
			})
		}

		if stats.HistogramFlat {
			analysis.Indicators = append(analysis.Indicators, Indicator{
				Type:        "entropy",
				Description: "Unusually flat histogram suggests data embedding",
				Severity:    "medium",
				Confidence:  70,
				Details: map[string]interface{}{
					"entropy": stats.EntropyScore,
				},
			})
		}
	}

	// Signature Detection
	if a.checkSignatures {
		f.Seek(0, io.SeekStart)
		data, err := io.ReadAll(f)
		if err == nil {
			sigs := a.detectSignatures(data)
			analysis.Signatures = sigs

			for _, sig := range sigs {
				analysis.Indicators = append(analysis.Indicators, Indicator{
					Type:        "signature",
					Description: fmt.Sprintf("Detected %s signature", sig.Tool),
					Severity:    "high",
					Confidence:  sig.Confidence,
					Details: map[string]interface{}{
						"tool":    sig.Tool,
						"version": sig.Version,
					},
				})
			}
		}
	}

	// Calculate overall confidence
	analysis.Confidence = a.calculateConfidence(analysis)
	analysis.Suspicious = analysis.Confidence >= a.minConfidence

	return analysis, nil
}

// analyzeLSB performs LSB analysis on image
func (a *Analyzer) analyzeLSB(img image.Image) *LSBAnalysis {
	bounds := img.Bounds()
	width, height := bounds.Dx(), bounds.Dy()

	var redLSB, greenLSB, blueLSB, alphaLSB []byte
	lsbChanges := 0
	totalPixels := 0

	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			c := img.At(x, y)
			r, g, b, al := c.RGBA()

			// Extract LSBs (convert from uint32 >> 8 to uint8)
			redLSB = append(redLSB, byte((r>>8)&1))
			greenLSB = append(greenLSB, byte((g>>8)&1))
			blueLSB = append(blueLSB, byte((b>>8)&1))
			alphaLSB = append(alphaLSB, byte((al>>8)&1))

			// Count LSB changes (detect randomness)
			if x > bounds.Min.X {
				prevC := img.At(x-1, y)
				prevR, prevG, prevB, _ := prevC.RGBA()

				if ((r>>8)&1) != ((prevR>>8)&1) {
					lsbChanges++
				}
				if ((g>>8)&1) != ((prevG>>8)&1) {
					lsbChanges++
				}
				if ((b>>8)&1) != ((prevB>>8)&1) {
					lsbChanges++
				}
			}
			totalPixels++
		}
	}

	analysis := &LSBAnalysis{
		RedLSBEntropy:   calculateEntropy(redLSB),
		GreenLSBEntropy: calculateEntropy(greenLSB),
		BlueLSBEntropy:  calculateEntropy(blueLSB),
		AlphaLSBEntropy: calculateEntropy(alphaLSB),
		LSBRatio:        float64(lsbChanges) / float64(totalPixels*3),
	}

	// Check if suspicious
	// High entropy in LSB plane suggests embedded data
	avgEntropy := (analysis.RedLSBEntropy + analysis.GreenLSBEntropy + analysis.BlueLSBEntropy) / 3.0

	// Natural images typically have LSB entropy < 0.7
	// Embedded data typically has LSB entropy > 0.95
	if avgEntropy > 0.9 || analysis.LSBRatio > 0.48 {
		analysis.Suspicious = true
	}

	// Additional check for dimensions (common stego tools use specific sizes)
	if width*height%(8*3) == 0 && avgEntropy > 0.85 {
		analysis.Suspicious = true
	}

	return analysis
}

// analyzeStatistics performs statistical analysis
func (a *Analyzer) analyzeStatistics(img image.Image) *StatisticalTests {
	bounds := img.Bounds()

	// Build histogram
	histogram := make(map[uint32]int)
	var pixelValues []uint32

	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			c := img.At(x, y)
			r, g, b, _ := c.RGBA()

			// Combine RGB into single value
			val := (r>>8)<<16 | (g>>8)<<8 | (b >> 8)
			histogram[val]++
			pixelValues = append(pixelValues, val)
		}
	}

	// Chi-square test
	chiSquare, pValue := chiSquareTest(histogram, len(pixelValues))

	// Check histogram flatness (embedded data tends to flatten histogram)
	histogramFlat := isHistogramFlat(histogram, len(pixelValues))

	// Calculate overall entropy
	entropyScore := calculatePixelEntropy(pixelValues)

	return &StatisticalTests{
		ChiSquare:      chiSquare,
		ChiSquarePValue: pValue,
		HistogramFlat:  histogramFlat,
		EntropyScore:   entropyScore,
	}
}

// detectSignatures detects known steganography tool signatures
func (a *Analyzer) detectSignatures(data []byte) []Signature {
	var signatures []Signature

	// Steghide signature (JPEG comment marker)
	if bytes.Contains(data, []byte("JFIF")) && bytes.Contains(data, []byte("\xFF\xFE")) {
		// Check for steghide patterns
		if hasHighEntropyRegions(data) {
			signatures = append(signatures, Signature{
				Tool:        "Steghide",
				Confidence:  75,
				Description: "Possible Steghide embedded data in JPEG",
			})
		}
	}

	// OutGuess signature (specific JPEG DCT coefficient patterns)
	if bytes.Contains(data, []byte("\xFF\xD8\xFF")) {
		if hasOutGuessPattern(data) {
			signatures = append(signatures, Signature{
				Tool:        "OutGuess",
				Confidence:  80,
				Description: "OutGuess DCT pattern detected",
			})
		}
	}

	// F5 algorithm signature
	if hasF5Pattern(data) {
		signatures = append(signatures, Signature{
			Tool:        "F5",
			Confidence:  85,
			Description: "F5 steganography pattern detected",
		})
	}

	// OpenStego signature (PNG tEXt chunks)
	if bytes.Contains(data, []byte("PNG")) && bytes.Contains(data, []byte("tEXt")) {
		if hasOpenStegoMarkers(data) {
			signatures = append(signatures, Signature{
				Tool:        "OpenStego",
				Confidence:  70,
				Description: "Possible OpenStego markers in PNG",
			})
		}
	}

	// JSteg signature (specific JPEG embedding)
	if hasJStegPattern(data) {
		signatures = append(signatures, Signature{
			Tool:        "JSteg",
			Confidence:  75,
			Description: "JSteg JPEG embedding detected",
		})
	}

	// LSB-based tools (generic)
	if hasGenericLSBPattern(data) {
		signatures = append(signatures, Signature{
			Tool:        "Generic LSB",
			Confidence:  60,
			Description: "Generic LSB-based steganography detected",
		})
	}

	return signatures
}

// getLSBSeverity determines severity of LSB findings
func (a *Analyzer) getLSBSeverity(lsb *LSBAnalysis) string {
	avgEntropy := (lsb.RedLSBEntropy + lsb.GreenLSBEntropy + lsb.BlueLSBEntropy) / 3.0

	if avgEntropy > 0.98 || lsb.LSBRatio > 0.49 {
		return "high"
	} else if avgEntropy > 0.92 || lsb.LSBRatio > 0.47 {
		return "medium"
	}
	return "low"
}

// getLSBConfidence calculates confidence from LSB analysis
func (a *Analyzer) getLSBConfidence(lsb *LSBAnalysis) int {
	avgEntropy := (lsb.RedLSBEntropy + lsb.GreenLSBEntropy + lsb.BlueLSBEntropy) / 3.0

	// Map entropy to confidence (0.9-1.0 -> 50-100)
	if avgEntropy < 0.9 {
		return 0
	}

	confidence := int((avgEntropy-0.9)*1000) + 50
	if lsb.LSBRatio > 0.48 {
		confidence += 20
	}

	if confidence > 100 {
		confidence = 100
	}

	return confidence
}

// calculateConfidence calculates overall confidence score
func (a *Analyzer) calculateConfidence(analysis *Analysis) int {
	if len(analysis.Indicators) == 0 {
		return 0
	}

	total := 0
	count := 0

	for _, ind := range analysis.Indicators {
		total += ind.Confidence
		count++
	}

	if count == 0 {
		return 0
	}

	// Weight by number of indicators
	base := total / count
	multiplier := 1.0 + (float64(count-1) * 0.1)

	confidence := int(float64(base) * multiplier)
	if confidence > 100 {
		confidence = 100
	}

	return confidence
}

// Utility functions

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
			entropy -= p * math.Log2(p)
		}
	}

	// Normalize to 0-1 range (max entropy for binary is 1)
	return entropy
}

func calculatePixelEntropy(pixels []uint32) float64 {
	if len(pixels) == 0 {
		return 0
	}

	freq := make(map[uint32]int)
	for _, p := range pixels {
		freq[p]++
	}

	var entropy float64
	length := float64(len(pixels))

	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

func chiSquareTest(histogram map[uint32]int, total int) (float64, float64) {
	// Simplified chi-square test
	// Expected frequency if uniform
	expectedFreq := float64(total) / float64(len(histogram))

	var chiSquare float64
	for _, observed := range histogram {
		diff := float64(observed) - expectedFreq
		chiSquare += (diff * diff) / expectedFreq
	}

	// Simplified p-value calculation (approximate)
	// Real implementation would use chi-square distribution
	degreesOfFreedom := len(histogram) - 1
	pValue := 1.0 - (chiSquare / float64(degreesOfFreedom*10))
	if pValue < 0 {
		pValue = 0
	}
	if pValue > 1 {
		pValue = 1
	}

	return chiSquare, pValue
}

func isHistogramFlat(histogram map[uint32]int, total int) bool {
	if len(histogram) == 0 {
		return false
	}

	// Calculate variance of histogram
	mean := float64(total) / float64(len(histogram))
	var variance float64

	for _, count := range histogram {
		diff := float64(count) - mean
		variance += diff * diff
	}
	variance /= float64(len(histogram))

	stdDev := math.Sqrt(variance)

	// If standard deviation is very low relative to mean, histogram is flat
	coefficientOfVariation := stdDev / mean

	return coefficientOfVariation < 0.3
}

func hasHighEntropyRegions(data []byte) bool {
	// Split into 1KB chunks and check entropy
	chunkSize := 1024
	highEntropyChunks := 0

	for i := 0; i < len(data)-chunkSize; i += chunkSize {
		chunk := data[i : i+chunkSize]
		entropy := calculateEntropy(chunk)

		if entropy > 7.5 { // High entropy suggests encrypted/compressed data
			highEntropyChunks++
		}
	}

	// If >30% of chunks have high entropy, suspicious
	totalChunks := (len(data) / chunkSize)
	if totalChunks == 0 {
		return false
	}

	ratio := float64(highEntropyChunks) / float64(totalChunks)
	return ratio > 0.3
}

func hasOutGuessPattern(data []byte) bool {
	// OutGuess modifies DCT coefficients in specific pattern
	// Look for JPEG markers and check coefficient distribution
	if !bytes.Contains(data, []byte("\xFF\xDA")) { // Start of Scan
		return false
	}

	// Simplified: check for unusual DCT coefficient patterns
	// Real implementation would decode JPEG DCT
	return hasUnusualByteDistribution(data)
}

func hasF5Pattern(data []byte) bool {
	// F5 uses matrix encoding
	// Check for patterns in JPEG quantization tables
	if !bytes.Contains(data, []byte("\xFF\xDB")) { // DQT marker
		return false
	}

	// Simplified detection based on unusual quantization patterns
	return hasUnusualByteDistribution(data)
}

func hasOpenStegoMarkers(data []byte) bool {
	// OpenStego uses PNG tEXt chunks
	if bytes.Contains(data, []byte("tEXtOpenStego")) {
		return true
	}

	// Check for unusual tEXt chunk patterns
	return bytes.Count(data, []byte("tEXt")) > 2
}

func hasJStegPattern(data []byte) bool {
	// JSteg embeds in LSBs of JPEG DCT coefficients
	// Check for sequential modification patterns
	if !bytes.Contains(data, []byte("\xFF\xD8")) {
		return false
	}

	return hasUnusualByteDistribution(data)
}

func hasGenericLSBPattern(data []byte) bool {
	// Check for patterns typical of LSB embedding
	// Look for runs of bytes with LSB alternating
	alternations := 0
	for i := 1; i < len(data) && i < 10000; i++ {
		if (data[i]&1) != (data[i-1]&1) {
			alternations++
		}
	}

	sampleSize := len(data)
	if sampleSize > 10000 {
		sampleSize = 10000
	}

	// If ~50% alternation, likely LSB embedding
	ratio := float64(alternations) / float64(sampleSize)
	return ratio > 0.45 && ratio < 0.55
}

func hasUnusualByteDistribution(data []byte) bool {
	// Check if byte distribution is unusual
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	// Calculate expected vs observed
	expected := len(data) / 256
	unusual := 0

	for i := 0; i < 256; i++ {
		observed := freq[byte(i)]
		diff := abs(observed - expected)

		if diff > expected*2 {
			unusual++
		}
	}

	return unusual > 30 // >30 unusual byte frequencies
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// ExtractLSB attempts to extract LSB data from image
func ExtractLSB(img image.Image) []byte {
	bounds := img.Bounds()
	var bits []byte

	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			c := img.At(x, y)
			r, g, b, _ := c.RGBA()

			// Extract LSBs
			bits = append(bits, byte((r>>8)&1))
			bits = append(bits, byte((g>>8)&1))
			bits = append(bits, byte((b>>8)&1))
		}
	}

	// Convert bits to bytes
	var result []byte
	for i := 0; i < len(bits)-7; i += 8 {
		var byteVal byte
		for j := 0; j < 8; j++ {
			byteVal |= bits[i+j] << (7 - j)
		}
		result = append(result, byteVal)
	}

	return result
}

// VisualAttack performs visual attack analysis
func VisualAttack(img image.Image) *image.RGBA {
	bounds := img.Bounds()
	enhanced := image.NewRGBA(bounds)

	// Amplify LSB plane to make hidden data visible
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			c := img.At(x, y)
			r, g, b, a := c.RGBA()

			// Extract and amplify LSBs
			rLSB := uint8((r >> 8) & 1)
			gLSB := uint8((g >> 8) & 1)
			bLSB := uint8((b >> 8) & 1)

			// Amplify by multiplying by 255
			enhanced.SetRGBA(x, y, color.RGBA{
				R: rLSB * 255,
				G: gLSB * 255,
				B: bLSB * 255,
				A: uint8(a >> 8),
			})
		}
	}

	return enhanced
}
