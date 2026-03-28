package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/afterdarksys/darkscan/pkg/privacy"
	"github.com/spf13/cobra"
)

var (
	privacyOutputFormat string
	privacyAutoClean    bool
	privacyInteractive  bool
)

var privacyCmd = &cobra.Command{
	Use:   "privacy",
	Short: "Scan for tracking cookies, browser hijacks, and privacy issues",
	Long: `Scan your system for privacy and tracking issues including:
  - Tracking cookies from advertising networks
  - Browser extensions with suspicious permissions
  - Browser hijacks (homepage, search engine, startup URLs)
  - Windows telemetry and data collection (Windows only)

This command helps you identify and remove tracking mechanisms.`,
	RunE: runPrivacyScan,
}

func init() {
	privacyCmd.Flags().StringVarP(&privacyOutputFormat, "output", "o", "text", "Output format (text, json)")
	privacyCmd.Flags().BoolVarP(&privacyAutoClean, "auto-clean", "a", false, "Automatically remove low-severity tracking (cookies only)")
	privacyCmd.Flags().BoolVarP(&privacyInteractive, "interactive", "i", false, "Interactively choose what to remove")
}

func runPrivacyScan(cmd *cobra.Command, args []string) error {
	scanner := privacy.NewScanner()

	fmt.Println("Scanning for privacy and tracking issues...")
	fmt.Println()

	// Show detected browsers
	browsers := scanner.GetBrowsers()
	if len(browsers) > 0 {
		fmt.Printf("Detected browsers: ")
		browserNames := make([]string, len(browsers))
		for i, b := range browsers {
			browserNames[i] = b.Name
		}
		fmt.Println(strings.Join(browserNames, ", "))
		fmt.Println()
	}

	// Perform scan
	result, err := scanner.Scan()
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Output results
	if privacyOutputFormat == "json" {
		return printPrivacyJSON(result)
	}

	printPrivacyText(result)

	// Auto-clean if requested
	if privacyAutoClean && result.TotalFindings > 0 {
		fmt.Println()
		cleanableFindings := getAutoCleanableFindings(result.Findings)
		if len(cleanableFindings) > 0 {
			fmt.Printf("Auto-cleaning %d low-severity tracking cookies...\n", len(cleanableFindings))
			removed, err := scanner.RemoveFindings(cleanableFindings)
			if err != nil {
				fmt.Printf("Cleaned %d items (with some errors)\n", removed)
			} else {
				fmt.Printf("Successfully cleaned %d items\n", removed)
			}
		}
	}

	// Interactive cleanup
	if privacyInteractive && result.TotalFindings > 0 {
		return runInteractiveCleanup(scanner, result.Findings)
	}

	return nil
}

func printPrivacyText(result *privacy.ScanResult) {
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("PRIVACY SCAN RESULTS")
	fmt.Println(strings.Repeat("=", 70))

	// Summary
	fmt.Printf("Total Issues Found:   %d\n", result.TotalFindings)
	if result.CriticalCount > 0 {
		fmt.Printf("  Critical:           %d\n", result.CriticalCount)
	}
	if result.HighCount > 0 {
		fmt.Printf("  High:               %d\n", result.HighCount)
	}
	if result.MediumCount > 0 {
		fmt.Printf("  Medium:             %d\n", result.MediumCount)
	}
	if result.LowCount > 0 {
		fmt.Printf("  Low:                %d\n", result.LowCount)
	}
	if result.InfoCount > 0 {
		fmt.Printf("  Info:               %d\n", result.InfoCount)
	}

	fmt.Printf("Browsers Scanned:     %d\n", result.BrowsersScanned)
	fmt.Printf("Scan Duration:        %s\n", result.ScanDuration.Round(1000000))

	if result.TotalFindings == 0 {
		fmt.Println("\n✓ No privacy issues detected!")
		fmt.Println(strings.Repeat("=", 70))
		return
	}

	// Group findings by category
	categories := make(map[string][]privacy.Finding)
	for _, finding := range result.Findings {
		categories[finding.Category] = append(categories[finding.Category], finding)
	}

	// Display findings by category
	for category, findings := range categories {
		fmt.Println()
		fmt.Printf("━━ %s (%d) ━━\n", strings.ToUpper(category), len(findings))

		for i, finding := range findings {
			if i >= 10 {
				fmt.Printf("  ... and %d more\n", len(findings)-10)
				break
			}

			severityMarker := getSeverityMarker(finding.Severity)
			fmt.Printf("  %s [%s] %s\n", severityMarker, finding.Browser, finding.Name)

			if verbose {
				fmt.Printf("      %s\n", finding.Description)
				if finding.Value != "" {
					valueDisplay := finding.Value
					if len(valueDisplay) > 60 {
						valueDisplay = valueDisplay[:57] + "..."
					}
					fmt.Printf("      Details: %s\n", valueDisplay)
				}
			}
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("=", 70))

	// Show cleanup suggestions
	if result.TotalFindings > 0 {
		fmt.Println()
		fmt.Println("💡 CLEANUP OPTIONS:")
		fmt.Println("  --auto-clean       Automatically remove low-severity tracking cookies")
		fmt.Println("  --interactive      Interactively choose what to remove")
		fmt.Println()
		fmt.Println("  Example: darkscan privacy --auto-clean")
		fmt.Println("           darkscan privacy --interactive")
	}
}

func printPrivacyJSON(result *privacy.ScanResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func getSeverityMarker(severity privacy.Severity) string {
	switch severity {
	case privacy.SeverityCritical:
		return "[!!]"
	case privacy.SeverityHigh:
		return "[!]"
	case privacy.SeverityMedium:
		return "[*]"
	case privacy.SeverityLow:
		return "[-]"
	default:
		return "[ ]"
	}
}

func getAutoCleanableFindings(findings []privacy.Finding) []privacy.Finding {
	cleanable := make([]privacy.Finding, 0)
	for _, finding := range findings {
		if finding.AutoRemove {
			cleanable = append(cleanable, finding)
		}
	}
	return cleanable
}

func runInteractiveCleanup(scanner *privacy.Scanner, findings []privacy.Finding) error {
	fmt.Println()
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("INTERACTIVE CLEANUP")
	fmt.Println(strings.Repeat("=", 70))

	// Group by category for easier selection
	categories := make(map[string][]privacy.Finding)
	for _, finding := range findings {
		if finding.Removable {
			categories[finding.Category] = append(categories[finding.Category], finding)
		}
	}

	totalRemoved := 0

	for category, catFindings := range categories {
		fmt.Printf("\n%s (%d items)\n", category, len(catFindings))
		fmt.Println(strings.Repeat("-", 70))

		for i, finding := range catFindings {
			fmt.Printf("\n[%d] %s\n", i+1, finding.Name)
			fmt.Printf("    Browser:  %s\n", finding.Browser)
			fmt.Printf("    Severity: %s\n", finding.Severity)
			fmt.Printf("    %s\n", finding.Description)

			fmt.Print("    Remove this item? (y/n/q to quit): ")
			var response string
			fmt.Scanln(&response)

			response = strings.ToLower(strings.TrimSpace(response))

			if response == "q" {
				fmt.Printf("\nRemoved %d items total.\n", totalRemoved)
				return nil
			}

			if response == "y" || response == "yes" {
				if err := scanner.RemoveFinding(finding); err != nil {
					fmt.Printf("    ✗ Failed to remove: %v\n", err)
				} else {
					fmt.Printf("    ✓ Removed successfully\n")
					totalRemoved++
				}
			} else {
				fmt.Printf("    ○ Skipped\n")
			}
		}
	}

	fmt.Printf("\n✓ Cleanup complete! Removed %d items.\n", totalRemoved)
	return nil
}
