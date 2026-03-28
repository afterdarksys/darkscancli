package stego_test

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"testing"

	"github.com/afterdarksys/darkscan/pkg/stego"
)

// Example: Basic steganography detection
func ExampleAnalyzer_AnalyzeFile() {
	// Create analyzer
	analyzer := stego.NewAnalyzer()

	// Analyze image
	analysis, err := analyzer.AnalyzeFile("suspect.png")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Check results
	if analysis.Suspicious {
		fmt.Printf("⚠️  Steganography detected! (Confidence: %d%%)\n", analysis.Confidence)

		for _, indicator := range analysis.Indicators {
			fmt.Printf("  - [%s] %s\n", indicator.Type, indicator.Description)
		}

		for _, sig := range analysis.Signatures {
			fmt.Printf("  - Tool: %s\n", sig.Tool)
		}
	} else {
		fmt.Printf("✓ Image appears clean\n")
	}
}

// Example: LSB extraction
func ExampleExtractLSB() {
	// Load image
	f, _ := os.Open("hidden.png")
	defer f.Close()

	img, _, _ := image.Decode(f)

	// Extract LSB data
	data := stego.ExtractLSB(img)

	// Check if it's text
	if isText(data) {
		fmt.Printf("Extracted text: %s\n", string(data[:100]))
	} else {
		fmt.Printf("Extracted %d bytes of binary data\n", len(data))
	}
}

// Example: Visual attack
func ExampleVisualAttack() {
	// Load image
	f, _ := os.Open("suspect.jpg")
	defer f.Close()

	img, _, _ := image.Decode(f)

	// Perform visual attack
	enhanced := stego.VisualAttack(img)

	// Save enhanced image
	out, _ := os.Create("visual_attack.png")
	defer out.Close()

	png.Encode(out, enhanced)

	fmt.Println("Visual attack image created")
	fmt.Println("Hidden data should be visible if present")
}

// Example: Integration with scanner
func ExampleEngine() {
	// Create steganography engine
	stegoEngine := stego.NewEngine()
	stegoEngine.SetMinConfidence(70)

	// In your scanner setup:
	// scanner.RegisterEngine(stegoEngine)

	fmt.Println("Steganography detection engine registered")
}

// Helper function
func isText(data []byte) bool {
	printable := 0
	sample := data
	if len(data) > 1000 {
		sample = data[:1000]
	}

	for _, b := range sample {
		if (b >= 32 && b <= 126) || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}

	return float64(printable)/float64(len(sample)) > 0.9
}

// TestCreateTestImage creates a test image with embedded LSB data
func TestCreateTestImage(t *testing.T) {
	// Create a simple image with LSB data
	width, height := 100, 100
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	// Fill with blue
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{R: 100, G: 100, B: 200, A: 255})
		}
	}

	// Embed message "HIDDEN" in LSB
	message := []byte("HIDDEN")
	bitIndex := 0

	for _, b := range message {
		for bit := 7; bit >= 0; bit-- {
			if bitIndex >= width*height*3 {
				break
			}

			// Get pixel position
			pixelIndex := bitIndex / 3
			channel := bitIndex % 3

			x := pixelIndex % width
			y := pixelIndex / width

			c := img.RGBAAt(x, y)

			// Extract bit
			bitVal := (b >> bit) & 1

			// Embed in appropriate channel
			switch channel {
			case 0: // Red
				c.R = (c.R & 0xFE) | bitVal
			case 1: // Green
				c.G = (c.G & 0xFE) | bitVal
			case 2: // Blue
				c.B = (c.B & 0xFE) | bitVal
			}

			img.SetRGBA(x, y, c)
			bitIndex++
		}
	}

	// Save test image
	buf := &bytes.Buffer{}
	err := png.Encode(buf, img)
	if err != nil {
		t.Fatalf("Failed to encode image: %v", err)
	}

	// Analyze it
	// Note: This would need to be written to a temp file first
	// or the analyzer would need to accept io.Reader
	t.Log("Test image created with LSB steganography")
}

// TestLSBDetection tests LSB detection capability
func TestLSBDetection(t *testing.T) {
	t.Skip("Requires image files - demonstration test only")

	// This test demonstrates LSB detection capabilities
	// In practice, you would save images to temp files and analyze them

	// Example usage:
	// 1. Create test images
	// 2. Save to temp files
	// 3. Use analyzer.AnalyzeFile() to test
	// 4. Compare results
}

func createCleanImage(width, height int) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	// Create gradient
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			r := uint8(x * 255 / width)
			g := uint8(y * 255 / height)
			b := uint8((x + y) * 255 / (width + height))
			img.Set(x, y, color.RGBA{R: r, G: g, B: b, A: 255})
		}
	}

	return img
}

func createStegoImage(width, height int, message []byte) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	// Fill with random-ish pattern
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{
				R: uint8((x*17 + y*13) % 256),
				G: uint8((x*23 + y*19) % 256),
				B: uint8((x*29 + y*31) % 256),
				A: 255,
			})
		}
	}

	// Embed message in LSB
	bitIndex := 0
	for _, b := range message {
		for bit := 7; bit >= 0; bit-- {
			if bitIndex >= width*height*3 {
				return img
			}

			pixelIndex := bitIndex / 3
			channel := bitIndex % 3

			x := pixelIndex % width
			y := pixelIndex / width

			c := img.RGBAAt(x, y)
			bitVal := (b >> bit) & 1

			switch channel {
			case 0:
				c.R = (c.R & 0xFE) | bitVal
			case 1:
				c.G = (c.G & 0xFE) | bitVal
			case 2:
				c.B = (c.B & 0xFE) | bitVal
			}

			img.SetRGBA(x, y, c)
			bitIndex++
		}
	}

	return img
}
