package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/afterdarksys/darkscan/pkg/carving"
	"github.com/afterdarksys/darkscan/pkg/vfs/local"
	"github.com/spf13/cobra"
)

var (
	outputDir     string
	reportFile    string
	minConfidence int
	maxFileSize   int64
	scanTypes     []string
	workers       int
	verbose       bool
	generateDFXML bool
)

var rootCmd = &cobra.Command{
	Use:   "darkscan-carve",
	Short: "Advanced file carving tool for forensic recovery",
	Long: `darkscan-carve is a sophisticated file carving tool that recovers files from
disk images, raw devices, and unallocated space using signature-based detection
and intelligent fragment assembly.`,
}

var scanCmd = &cobra.Command{
	Use:   "scan <source>",
	Short: "Scan a disk image or device for recoverable files",
	Long: `Scan performs a comprehensive analysis of the source, identifying all recoverable
files using signature-based carving. Results are saved to a DFXML report.`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

var recoverCmd = &cobra.Command{
	Use:   "recover <report> <output-dir>",
	Short: "Recover files from a DFXML scan report",
	Long:  `Recover extracts files identified in a previous scan to the specified output directory.`,
	Args:  cobra.ExactArgs(2),
	RunE:  runRecover,
}

var formatsCmd = &cobra.Command{
	Use:   "formats",
	Short: "List supported file formats",
	RunE:  listFormats,
}

var statsCmd = &cobra.Command{
	Use:   "stats <report>",
	Short: "Display statistics from a DFXML report",
	Args:  cobra.ExactArgs(1),
	RunE:  showStats,
}

func init() {
	// Scan command flags
	scanCmd.Flags().StringVarP(&outputDir, "output", "o", "./carved", "Output directory for recovered files")
	scanCmd.Flags().StringVarP(&reportFile, "report", "r", "scan-report.xml", "DFXML report file")
	scanCmd.Flags().IntVarP(&minConfidence, "min-confidence", "c", 50, "Minimum confidence score (0-100)")
	scanCmd.Flags().Int64VarP(&maxFileSize, "max-size", "s", 100, "Maximum file size in MB")
	scanCmd.Flags().StringSliceVarP(&scanTypes, "types", "t", []string{}, "File types to scan for (empty = all)")
	scanCmd.Flags().IntVarP(&workers, "workers", "w", 4, "Number of concurrent workers")
	scanCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	scanCmd.Flags().BoolVar(&generateDFXML, "dfxml", true, "Generate DFXML report")

	// Recover command flags
	recoverCmd.Flags().IntVarP(&minConfidence, "min-confidence", "c", 70, "Minimum confidence to recover")
	recoverCmd.Flags().StringSliceVarP(&scanTypes, "types", "t", []string{}, "File types to recover (empty = all)")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(recoverCmd)
	rootCmd.AddCommand(formatsCmd)
	rootCmd.AddCommand(statsCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	source := args[0]

	fmt.Printf("DarkScan File Carver v1.0.0\n")
	fmt.Printf("Scanning: %s\n", source)
	fmt.Printf("Output: %s\n", outputDir)
	fmt.Printf("\n")

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	// Open source
	partition, err := local.NewPartition(source)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer partition.Close()

	// Get file size
	stat, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("stat source: %w", err)
	}
	volumeSize := stat.Size()

	// Create carver
	opts := carving.Options{
		BlockSize:     4096,
		MaxFileSize:   maxFileSize * 1024 * 1024,
		MinConfidence: minConfidence,
		ValidateFiles: true,
	}

	// Filter signatures by type if specified
	if len(scanTypes) > 0 {
		opts.Signatures = filterSignatures(scanTypes)
	}

	if verbose {
		opts.Progress = func(offset, total int64, filesFound int) {
			pct := int64(0)
			if total > 0 {
				pct = offset * 100 / total
			}
			fmt.Printf("\rScanning: %d%% (%d files found)", pct, filesFound)
		}
	}

	carver := carving.NewCarver(opts)

	// Create DFXML report
	var report *carving.DFXMLReport
	if generateDFXML {
		report = carving.NewDFXMLReport()
		report.Source.ImageFilename = source
		report.Source.VolumeSize = volumeSize
		report.RunInfo.ScanType = "full"
	}

	// Perform carving
	fmt.Printf("Carving files...\n")
	startTime := time.Now()

	ctx := context.Background()
	carved, err := carver.CarveReader(ctx, partition, 0, volumeSize)
	if err != nil {
		return fmt.Errorf("carving failed: %w", err)
	}

	duration := time.Since(startTime)

	if verbose {
		fmt.Printf("\n")
	}

	// Save carved files and populate report
	savedCount := 0
	seen := make(map[string]bool)
	for i, file := range carved {
		if file.Confidence < minConfidence {
			continue
		}

		// Deduplication by SHA-256
		if file.SHA256 != "" {
			if seen[file.SHA256] {
				if verbose {
					fmt.Printf("  Skipping duplicate (sha256: %s)\n", file.SHA256[:16])
				}
				continue
			}
			seen[file.SHA256] = true
		}

		// Generate output filename
		filename := fmt.Sprintf("%06d_%s_0x%X.%s",
			i, file.Type, file.Offset, file.Extension)
		outputPath := filepath.Join(outputDir, filename)

		// Save file
		if err := os.WriteFile(outputPath, file.Data, 0644); err != nil {
			fmt.Printf("Failed to save %s: %v\n", filename, err)
			continue
		}

		savedCount++

		// Add to report
		if report != nil {
			report.AddCarvedFile(file, filename)
		}

		if verbose {
			fmt.Printf("  Recovered: %s (%d bytes, confidence: %d%%)\n",
				filename, file.Size, file.Confidence)
		}
	}

	// Finalize and save report
	if report != nil {
		report.Finalize()
		reportPath := filepath.Join(outputDir, reportFile)
		if err := report.WriteToFile(reportPath); err != nil {
			fmt.Printf("Warning: Failed to write report: %v\n", err)
		} else {
			fmt.Printf("\nDFXML report saved: %s\n", reportPath)
		}
	}

	// Print summary
	fmt.Printf("\n=== Scan Complete ===\n")
	fmt.Printf("Duration: %s\n", duration)
	fmt.Printf("Files found: %d\n", len(carved))
	fmt.Printf("Files recovered: %d\n", savedCount)
	fmt.Printf("Output directory: %s\n", outputDir)

	if report != nil {
		stats := report.GetStatistics()
		fmt.Printf("\nStatistics:\n")
		fmt.Printf("  Total bytes: %d MB\n", stats.TotalBytes/1024/1024)
		fmt.Printf("  Average confidence: %.1f%%\n", stats.AverageConfidence)
		fmt.Printf("  Complete files: %d\n", stats.CompleteFiles)
		fmt.Printf("  Fragmented files: %d\n", stats.FragmentedFiles)

		fmt.Printf("\nFiles by type:\n")
		for fileType, count := range stats.FilesByType {
			fmt.Printf("  %s: %d\n", fileType, count)
		}
	}

	return nil
}

func runRecover(cmd *cobra.Command, args []string) error {
	reportPath := args[0]
	outputDir := args[1]

	fmt.Printf("Recovering files from report: %s\n", reportPath)
	fmt.Printf("Output directory: %s\n", outputDir)

	// Parse DFXML report
	xmlData, err := os.ReadFile(reportPath)
	if err != nil {
		return fmt.Errorf("read report: %w", err)
	}

	var report carving.DFXMLReport
	if err := xml.Unmarshal(xmlData, &report); err != nil {
		return fmt.Errorf("parse report: %w", err)
	}

	// Open source image
	partition, err := local.NewPartition(report.Source.ImageFilename)
	if err != nil {
		return fmt.Errorf("open source image %s: %w", report.Source.ImageFilename, err)
	}
	defer partition.Close()

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	// Build type filter map
	typeFilter := make(map[string]bool)
	for _, t := range scanTypes {
		typeFilter[strings.ToLower(t)] = true
	}

	recovered := 0
	skipped := 0
	errors := 0

	for _, file := range report.Files {
		// Skip below confidence threshold
		if file.CarvingInfo != nil && file.CarvingInfo.Confidence < minConfidence {
			skipped++
			continue
		}

		// Skip filtered types
		if len(typeFilter) > 0 && !typeFilter[strings.ToLower(file.FileType)] {
			skipped++
			continue
		}

		// Concatenate all byte runs
		var fileData []byte
		for _, run := range file.ByteRuns {
			buf := make([]byte, run.Length)
			n, err := partition.ReadAt(buf, run.ImageOffset)
			if err != nil && err != io.EOF {
				fmt.Printf("  Error reading %s at offset %d: %v\n", file.Filename, run.ImageOffset, err)
				errors++
				break
			}
			fileData = append(fileData, buf[:n]...)
		}

		if len(fileData) == 0 {
			skipped++
			continue
		}

		// Write to output directory
		outPath := filepath.Join(outputDir, filepath.Base(file.Filename))
		if err := os.WriteFile(outPath, fileData, 0644); err != nil {
			fmt.Printf("  Error writing %s: %v\n", file.Filename, err)
			errors++
			continue
		}

		recovered++
		fmt.Printf("  Recovered: %s (%d bytes)\n", filepath.Base(file.Filename), len(fileData))
	}

	fmt.Printf("\n=== Recovery Complete ===\n")
	fmt.Printf("Recovered: %d files\n", recovered)
	fmt.Printf("Skipped:   %d files\n", skipped)
	fmt.Printf("Errors:    %d\n", errors)

	return nil
}

func listFormats(cmd *cobra.Command, args []string) error {
	fmt.Printf("Supported File Formats:\n\n")

	categories := make(map[string][]carving.FileSignature)

	for _, sig := range carving.Signatures {
		categories[sig.Category] = append(categories[sig.Category], sig)
	}

	for category, sigs := range categories {
		fmt.Printf("=== %s ===\n", category)
		for _, sig := range sigs {
			footer := "No"
			if sig.HasFooter {
				footer = "Yes"
			}
			fmt.Printf("  %-20s .%-10s %s (Footer: %s)\n",
				sig.Name, sig.Extension, sig.MIMEType, footer)
		}
		fmt.Printf("\n")
	}

	fmt.Printf("Total formats: %d\n", len(carving.Signatures))

	return nil
}

func showStats(cmd *cobra.Command, args []string) error {
	reportPath := args[0]

	xmlData, err := os.ReadFile(reportPath)
	if err != nil {
		return fmt.Errorf("read report: %w", err)
	}

	var report carving.DFXMLReport
	if err := xml.Unmarshal(xmlData, &report); err != nil {
		return fmt.Errorf("parse report: %w", err)
	}

	stats := report.GetStatistics()

	fmt.Printf("=== DFXML Report Statistics ===\n\n")
	fmt.Printf("Source image:       %s\n", report.Source.ImageFilename)
	fmt.Printf("Scan type:          %s\n", report.RunInfo.ScanType)

	if !report.RunInfo.StartTime.IsZero() {
		fmt.Printf("Start time:         %s\n", report.RunInfo.StartTime.Format(time.RFC3339))
	}
	if !report.RunInfo.EndTime.IsZero() {
		fmt.Printf("End time:           %s\n", report.RunInfo.EndTime.Format(time.RFC3339))
		if !report.RunInfo.StartTime.IsZero() {
			duration := report.RunInfo.EndTime.Sub(report.RunInfo.StartTime)
			fmt.Printf("Scan duration:      %s\n", duration)
		}
	}

	fmt.Printf("\n--- File Summary ---\n")
	fmt.Printf("Total files:        %d\n", stats.TotalFiles)
	fmt.Printf("Total bytes:        %.2f MB\n", float64(stats.TotalBytes)/1024/1024)
	fmt.Printf("Average confidence: %.1f%%\n", stats.AverageConfidence)
	fmt.Printf("Complete files:     %d\n", stats.CompleteFiles)
	fmt.Printf("Fragmented files:   %d\n", stats.FragmentedFiles)

	if len(stats.FilesByType) > 0 {
		fmt.Printf("\n--- Files by Type ---\n")

		type typeCount struct {
			name  string
			count int
		}
		sorted := make([]typeCount, 0, len(stats.FilesByType))
		for t, c := range stats.FilesByType {
			sorted = append(sorted, typeCount{t, c})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].count > sorted[j].count
		})
		for _, tc := range sorted {
			fmt.Printf("  %-20s %d\n", tc.name, tc.count)
		}
	}

	return nil
}

func filterSignatures(types []string) []carving.FileSignature {
	filtered := make([]carving.FileSignature, 0)

	typeMap := make(map[string]bool)
	for _, t := range types {
		typeMap[strings.ToLower(t)] = true
	}

	for _, sig := range carving.Signatures {
		if typeMap[strings.ToLower(sig.Extension)] || typeMap[strings.ToLower(sig.Category)] {
			filtered = append(filtered, sig)
		}
	}

	return filtered
}
