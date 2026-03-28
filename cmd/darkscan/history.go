package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/afterdarksys/darkscan/pkg/store"
	"github.com/spf13/cobra"
)

var (
	historyLimit     int
	historyInfected  bool
	historyClean     bool
	historyShowStats bool
	searchLimit      int
)

func getStorePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp"
	}
	return filepath.Join(home, ".darkscan", "scans.db")
}

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "Show a log of recent scans",
	Long:  `Display scan history with optional filtering by infection status and statistics.`,
	RunE:  runHistory,
}

var searchCmd = &cobra.Command{
	Use:   "search [query]",
	Short: "Search scan history by hash, path, or threat name",
	Args:  cobra.ExactArgs(1),
	RunE:  runSearch,
}

func runHistory(cmd *cobra.Command, args []string) error {
	db, err := store.New(getStorePath())
	if err != nil {
		return err
	}
	defer db.Close()

	records, err := db.GetRecentScans(historyLimit)
	if err != nil {
		return err
	}

	// Filter by infection status if specified
	if historyInfected || historyClean {
		filtered := make([]store.ScanRecord, 0)
		for _, r := range records {
			if historyInfected && r.Infected {
				filtered = append(filtered, r)
			} else if historyClean && !r.Infected {
				filtered = append(filtered, r)
			}
		}
		records = filtered
	}

	if historyShowStats {
		printHistoryStats(records)
		fmt.Println()
	}

	printRecords(records)
	return nil
}

func runSearch(cmd *cobra.Command, args []string) error {
	db, err := store.New(getStorePath())
	if err != nil {
		return err
	}
	defer db.Close()

	records, err := db.SearchScans(args[0], searchLimit)
	if err != nil {
		return err
	}

	if len(records) == 0 {
		fmt.Printf("No results found for: %s\n", args[0])
		return nil
	}

	fmt.Printf("Found %d results for: %s\n\n", len(records), args[0])
	printRecords(records)
	return nil
}

func printRecords(records []store.ScanRecord) {
	if len(records) == 0 {
		fmt.Println("No scan records found.")
		return
	}

	fmt.Printf("%-20s %-10s %-45s %s\n", "TIME", "STATUS", "FILE/HASH", "THREATS")
	fmt.Println(strings.Repeat("-", 120))

	for _, r := range records {
		status := "CLEAN"
		if r.Infected {
			status = "INFECTED"
		}
		path := r.FilePath
		if len(path) > 43 {
			path = "..." + path[len(path)-40:]
		}

		threats := r.Threats
		if len(threats) > 50 {
			threats = threats[:47] + "..."
		}

		fmt.Printf("%-20s %-10s %-45s %s\n",
			r.ScanTime.Format("2006-01-02 15:04"),
			status,
			path,
			threats,
		)
	}
	fmt.Printf("\nTotal: %d scans\n", len(records))
}

func printHistoryStats(records []store.ScanRecord) {
	total := len(records)
	infected := 0
	clean := 0

	threatMap := make(map[string]int)

	for _, r := range records {
		if r.Infected {
			infected++
			if r.Threats != "" {
				threats := strings.Split(r.Threats, ",")
				for _, t := range threats {
					t = strings.TrimSpace(t)
					if t != "" {
						threatMap[t]++
					}
				}
			}
		} else {
			clean++
		}
	}

	fmt.Println("Scan History Statistics:")
	fmt.Printf("  Total scans:     %d\n", total)
	fmt.Printf("  Infected:        %d (%.1f%%)\n", infected, float64(infected)/float64(total)*100)
	fmt.Printf("  Clean:           %d (%.1f%%)\n", clean, float64(clean)/float64(total)*100)

	if len(threatMap) > 0 {
		fmt.Println("\n  Top Threats:")
		count := 0
		for threat, occurrences := range threatMap {
			if count >= 10 {
				break
			}
			fmt.Printf("    - %s: %d\n", threat, occurrences)
			count++
		}
	}
}

func init() {
	historyCmd.Flags().IntVarP(&historyLimit, "limit", "l", 50, "Limit number of results")
	historyCmd.Flags().BoolVar(&historyInfected, "infected", false, "Show only infected files")
	historyCmd.Flags().BoolVar(&historyClean, "clean", false, "Show only clean files")
	historyCmd.Flags().BoolVarP(&historyShowStats, "stats", "s", false, "Show statistics summary")

	searchCmd.Flags().IntVarP(&searchLimit, "limit", "l", 50, "Limit number of results")
}
