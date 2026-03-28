package main

import (
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"strings"

	"github.com/afterdarksys/darkscan/pkg/stego"
	"github.com/spf13/cobra"
)

var (
	minConfidence int
	outputDir     string
	extractLSB    bool
	visualAttack  bool
	verbose       bool
	scanDir       bool
)

var rootCmd = &cobra.Command{
	Use:   "darkscan-stego",
	Short: "Advanced steganography detection and analysis",
	Long: `darkscan-stego detects hidden data in images using multiple techniques:
- LSB (Least Significant Bit) analysis
- Statistical analysis (chi-square, histogram)
- Known tool signature detection (Steghide, OutGuess, F5, etc.)
- Visual attack analysis`,
}

var scanCmd = &cobra.Command{
	Use:   "scan <file-or-directory>",
	Short: "Scan image(s) for steganography",
	Args:  cobra.ExactArgs(1),
	RunE:  runScan,
}

var extractCmd = &cobra.Command{
	Use:   "extract <image>",
	Short: "Extract LSB data from image",
	Args:  cobra.ExactArgs(1),
	RunE:  runExtract,
}

var visualCmd = &cobra.Command{
	Use:   "visual <image> <output>",
	Short: "Generate visual attack image",
	Args:  cobra.ExactArgs(2),
	RunE:  runVisual,
}

func init() {
	scanCmd.Flags().IntVarP(&minConfidence, "min-confidence", "c", 50, "Minimum confidence threshold")
	scanCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	scanCmd.Flags().BoolVarP(&scanDir, "recursive", "r", false, "Scan directory recursively")

	extractCmd.Flags().StringVarP(&outputDir, "output", "o", ".", "Output directory for extracted data")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(extractCmd)
	rootCmd.AddCommand(visualCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	path := args[0]

	stat, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}

	analyzer := stego.NewAnalyzer()

	if stat.IsDir() {
		return scanDirectory(path, analyzer)
	}

	return scanFile(path, analyzer)
}

func scanDirectory(dir string, analyzer *stego.Analyzer) error {
	fmt.Printf("Scanning directory: %s\n\n", dir)

	imageExts := map[string]bool{
		".jpg":  true,
		".jpeg": true,
		".png":  true,
		".gif":  true,
		".bmp":  true,
	}

	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			ext := strings.ToLower(filepath.Ext(path))
			if imageExts[ext] {
				files = append(files, path)
			}
		}

		if !scanDir && path != dir && info.IsDir() {
			return filepath.SkipDir
		}

		return nil
	})

	if err != nil {
		return err
	}

	fmt.Printf("Found %d images to scan\n\n", len(files))

	suspicious := 0
	for i, file := range files {
		fmt.Printf("[%d/%d] Scanning: %s\n", i+1, len(files), filepath.Base(file))

		analysis, err := analyzer.AnalyzeFile(file)
		if err != nil {
			fmt.Printf("  Error: %v\n", err)
			continue
		}

		if analysis.Suspicious {
			suspicious++
			printAnalysis(analysis, true)
		} else if verbose {
			printAnalysis(analysis, false)
		}

		fmt.Println()
	}

	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("Total scanned: %d\n", len(files))
	fmt.Printf("Suspicious: %d\n", suspicious)
	fmt.Printf("Clean: %d\n", len(files)-suspicious)

	return nil
}

func scanFile(path string, analyzer *stego.Analyzer) error {
	fmt.Printf("Analyzing: %s\n\n", path)

	analysis, err := analyzer.AnalyzeFile(path)
	if err != nil {
		return err
	}

	printAnalysis(analysis, true)

	return nil
}

func printAnalysis(analysis *stego.Analysis, detailed bool) {
	if analysis.Suspicious {
		fmt.Printf("  🚨 SUSPICIOUS (Confidence: %d%%)\n", analysis.Confidence)
	} else {
		fmt.Printf("  ✓ Clean (Confidence: %d%%)\n", analysis.Confidence)
	}

	fmt.Printf("  Format: %s, Size: %dx%d\n", analysis.Format, analysis.Dimensions.X, analysis.Dimensions.Y)

	if !detailed && !analysis.Suspicious {
		return
	}

	// Print indicators
	if len(analysis.Indicators) > 0 {
		fmt.Printf("\n  Indicators:\n")
		for _, ind := range analysis.Indicators {
			icon := getSeverityIcon(ind.Severity)
			fmt.Printf("    %s [%s] %s (Confidence: %d%%)\n",
				icon, strings.ToUpper(ind.Type), ind.Description, ind.Confidence)

			if verbose && len(ind.Details) > 0 {
				for k, v := range ind.Details {
					fmt.Printf("      - %s: %v\n", k, v)
				}
			}
		}
	}

	// Print LSB analysis
	if analysis.LSBAnalysis != nil && detailed {
		lsb := analysis.LSBAnalysis
		fmt.Printf("\n  LSB Analysis:\n")
		fmt.Printf("    Red entropy:   %.4f\n", lsb.RedLSBEntropy)
		fmt.Printf("    Green entropy: %.4f\n", lsb.GreenLSBEntropy)
		fmt.Printf("    Blue entropy:  %.4f\n", lsb.BlueLSBEntropy)
		fmt.Printf("    LSB ratio:     %.4f\n", lsb.LSBRatio)

		if lsb.Suspicious {
			fmt.Printf("    Status: ⚠️  SUSPICIOUS\n")
		}
	}

	// Print statistical tests
	if analysis.StatisticalTests != nil && detailed {
		stats := analysis.StatisticalTests
		fmt.Printf("\n  Statistical Tests:\n")
		fmt.Printf("    Chi-square:    %.2f (p=%.4f)\n", stats.ChiSquare, stats.ChiSquarePValue)
		fmt.Printf("    Entropy:       %.4f\n", stats.EntropyScore)
		fmt.Printf("    Histogram:     ")
		if stats.HistogramFlat {
			fmt.Printf("⚠️  Suspiciously flat\n")
		} else {
			fmt.Printf("✓ Normal\n")
		}
	}

	// Print signatures
	if len(analysis.Signatures) > 0 {
		fmt.Printf("\n  Detected Tools:\n")
		for _, sig := range analysis.Signatures {
			fmt.Printf("    🔍 %s", sig.Tool)
			if sig.Version != "" {
				fmt.Printf(" v%s", sig.Version)
			}
			fmt.Printf(" (Confidence: %d%%)\n", sig.Confidence)
			if sig.Description != "" {
				fmt.Printf("       %s\n", sig.Description)
			}
		}
	}
}

func getSeverityIcon(severity string) string {
	switch severity {
	case "high":
		return "🔴"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "⚪"
	}
}

func runExtract(cmd *cobra.Command, args []string) error {
	imagePath := args[0]

	fmt.Printf("Extracting LSB data from: %s\n", imagePath)

	// Open and decode image
	f, err := os.Open(imagePath)
	if err != nil {
		return err
	}
	defer f.Close()

	img, _, err := image.Decode(f)
	if err != nil {
		return fmt.Errorf("decode image: %w", err)
	}

	// Extract LSB
	data := stego.ExtractLSB(img)

	// Save to file
	outputPath := filepath.Join(outputDir, filepath.Base(imagePath)+".lsb.bin")
	err = os.WriteFile(outputPath, data, 0644)
	if err != nil {
		return err
	}

	fmt.Printf("Extracted %d bytes to: %s\n", len(data), outputPath)

	// Try to detect if it's text
	printableCount := 0
	for _, b := range data[:min(len(data), 1000)] {
		if (b >= 32 && b <= 126) || b == '\n' || b == '\r' || b == '\t' {
			printableCount++
		}
	}

	if float64(printableCount)/float64(min(len(data), 1000)) > 0.9 {
		fmt.Printf("\nExtracted data appears to be text:\n")
		fmt.Printf("---\n%s\n---\n", string(data[:min(len(data), 500)]))
	}

	return nil
}

func runVisual(cmd *cobra.Command, args []string) error {
	imagePath := args[0]
	outputPath := args[1]

	fmt.Printf("Generating visual attack image...\n")

	// Open and decode image
	f, err := os.Open(imagePath)
	if err != nil {
		return err
	}
	defer f.Close()

	img, _, err := image.Decode(f)
	if err != nil {
		return fmt.Errorf("decode image: %w", err)
	}

	// Perform visual attack
	enhanced := stego.VisualAttack(img)

	// Save result
	out, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer out.Close()

	err = png.Encode(out, enhanced)
	if err != nil {
		return err
	}

	fmt.Printf("Visual attack image saved to: %s\n", outputPath)
	fmt.Printf("Hidden data (if present) should be visible in the output image.\n")

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
