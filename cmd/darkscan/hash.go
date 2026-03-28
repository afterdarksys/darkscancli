package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/afterdarksys/darkscan/pkg/config"
	"github.com/afterdarksys/darkscan/pkg/store"
	"github.com/spf13/cobra"
)

var (
	hashFormat   string
	hashInfected bool
	hashClean    bool
	hashOutputFile string
	hashRetention int
)

var hashCmd = &cobra.Command{
	Use:   "hash",
	Short: "Manage file hash cache",
	Long:  `Commands for managing the local file hash database and cache.`,
}

var hashStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show hash cache statistics",
	RunE:  runHashStats,
}

var hashExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export hashes from cache",
	Long:  `Export file hashes to CSV or JSON format for sharing or analysis.`,
	RunE:  runHashExport,
}

var hashCleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Clean old hash cache entries",
	RunE:  runHashClean,
}

func init() {
	hashExportCmd.Flags().StringVarP(&hashFormat, "format", "f", "csv", "Export format (csv, json)")
	hashExportCmd.Flags().BoolVar(&hashInfected, "infected", false, "Export only infected file hashes")
	hashExportCmd.Flags().BoolVar(&hashClean, "clean", false, "Export only clean file hashes")
	hashExportCmd.Flags().StringVarP(&hashOutputFile, "output", "o", "", "Output file (default: stdout)")

	hashCleanCmd.Flags().IntVarP(&hashRetention, "days", "d", 90, "Retention period in days")

	hashCmd.AddCommand(hashStatsCmd)
	hashCmd.AddCommand(hashExportCmd)
	hashCmd.AddCommand(hashCleanCmd)
}

func runHashStats(cmd *cobra.Command, args []string) error {
	darkscanDir, err := config.GetDarkscanDir()
	if err != nil {
		return fmt.Errorf("failed to get darkscan dir: %w", err)
	}

	dbPath := filepath.Join(darkscanDir, "scans.db")
	st, err := store.New(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer st.Close()

	total, infected, clean, err := st.GetHashStats()
	if err != nil {
		return fmt.Errorf("failed to get stats: %w", err)
	}

	fmt.Printf("Hash Cache Statistics:\n")
	fmt.Printf("  Total hashes:    %d\n", total)
	fmt.Printf("  Infected:        %d\n", infected)
	fmt.Printf("  Clean:           %d\n", clean)

	return nil
}

func runHashExport(cmd *cobra.Command, args []string) error {
	// Determine which hashes to export
	exportInfected := hashInfected
	if !hashInfected && !hashClean {
		// If neither flag specified, export both (starting with infected)
		exportInfected = true
	}

	darkscanDir, err := config.GetDarkscanDir()
	if err != nil {
		return fmt.Errorf("failed to get darkscan dir: %w", err)
	}

	dbPath := filepath.Join(darkscanDir, "scans.db")
	st, err := store.New(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer st.Close()

	entries, err := st.ExportHashes(hashFormat, exportInfected)
	if err != nil {
		return fmt.Errorf("failed to export hashes: %w", err)
	}

	// If clean flag is also set, append clean hashes
	if hashClean && hashInfected {
		cleanEntries, err := st.ExportHashes(hashFormat, false)
		if err != nil {
			return fmt.Errorf("failed to export clean hashes: %w", err)
		}
		entries = append(entries, cleanEntries...)
	} else if hashClean {
		// Only clean requested
		entries, err = st.ExportHashes(hashFormat, false)
		if err != nil {
			return fmt.Errorf("failed to export clean hashes: %w", err)
		}
	}

	// Determine output destination
	var output *os.File
	if hashOutputFile != "" {
		output, err = os.Create(hashOutputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer output.Close()
	} else {
		output = os.Stdout
	}

	// Export based on format
	switch hashFormat {
	case "csv":
		return exportHashesCSV(output, entries)
	case "json":
		return exportHashesJSON(output, entries)
	default:
		return fmt.Errorf("unsupported format: %s", hashFormat)
	}
}

func exportHashesCSV(output *os.File, entries []store.HashCacheEntry) error {
	writer := csv.NewWriter(output)
	defer writer.Flush()

	// Write header
	if err := writer.Write([]string{"MD5", "SHA1", "SHA256", "FileSize", "Infected", "Threats", "FirstSeen", "LastSeen", "ScanCount"}); err != nil {
		return err
	}

	// Write data
	for _, entry := range entries {
		infected := "false"
		if entry.Infected {
			infected = "true"
		}
		record := []string{
			entry.MD5,
			entry.SHA1,
			entry.SHA256,
			fmt.Sprintf("%d", entry.FileSize),
			infected,
			entry.Threats,
			entry.FirstSeen.Format("2006-01-02 15:04:05"),
			entry.LastSeen.Format("2006-01-02 15:04:05"),
			fmt.Sprintf("%d", entry.ScanCount),
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

func exportHashesJSON(output *os.File, entries []store.HashCacheEntry) error {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(map[string]interface{}{
		"total":  len(entries),
		"hashes": entries,
	})
}

func runHashClean(cmd *cobra.Command, args []string) error {
	darkscanDir, err := config.GetDarkscanDir()
	if err != nil {
		return fmt.Errorf("failed to get darkscan dir: %w", err)
	}

	dbPath := filepath.Join(darkscanDir, "scans.db")
	st, err := store.New(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer st.Close()

	removed, err := st.CleanHashCache(hashRetention)
	if err != nil {
		return fmt.Errorf("failed to clean cache: %w", err)
	}

	fmt.Printf("Removed %d hash entries older than %d days\n", removed, hashRetention)
	return nil
}
