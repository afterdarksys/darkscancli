package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/afterdarksys/darkscan/pkg/filetype"
	"github.com/spf13/cobra"
)

var (
	identifyOutputFormat string
	identifyVerbose      bool
)

var identifyCmd = &cobra.Command{
	Use:   "identify [file...]",
	Short: "Identify file types and detect spoofing",
	Long: `Identify file types using magic byte signatures and detect extension spoofing.
This command helps detect malware disguised as innocent file types.`,
	Args: cobra.MinimumNArgs(1),
	RunE: runIdentify,
}

func init() {
	identifyCmd.Flags().StringVarP(&identifyOutputFormat, "output", "o", "text", "Output format (text, json)")
	identifyCmd.Flags().BoolVarP(&identifyVerbose, "verbose", "v", false, "Show detailed information")
}

func runIdentify(cmd *cobra.Command, args []string) error {
	detector := filetype.NewDetector()
	results := make([]*filetype.FileType, 0, len(args))

	for _, path := range args {
		result, err := detector.IdentifyFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error analyzing %s: %v\n", path, err)
			continue
		}

		// Store path in a field we can access later
		// We'll use Description to include path for now, or create wrapper
		results = append(results, result)

		if identifyOutputFormat == "text" {
			printIdentifyText(path, result)
		}
	}

	if identifyOutputFormat == "json" {
		return printIdentifyJSON(args, results)
	}

	// Print summary if multiple files
	if len(args) > 1 {
		printIdentifySummary(results)
	}

	return nil
}

func printIdentifyText(path string, ft *filetype.FileType) {
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("FILE: %s\n", path)
	fmt.Println(strings.Repeat("-", 70))

	// Risk indicator
	riskLevel := ft.GetRiskLevel()
	riskColor := ""
	switch riskLevel {
	case "CRITICAL":
		riskColor = "[!!]"
	case "HIGH":
		riskColor = "[!]"
	case "MEDIUM":
		riskColor = "[*]"
	default:
		riskColor = "[ ]"
	}

	fmt.Printf("Risk Level:     %s %s\n", riskColor, riskLevel)

	// Spoofing warning
	if ft.IsSpoofed {
		fmt.Println()
		fmt.Println("⚠️  WARNING: FILE TYPE SPOOFING DETECTED!")
		fmt.Printf("    Declared Extension: .%s\n", ft.DeclaredExt)
		fmt.Printf("    Actual File Type:   .%s (%s)\n", ft.ActualType, ft.Description)
		fmt.Println("    This file may be malicious!")
		fmt.Println()
	}

	// File type information
	fmt.Printf("Type:           %s\n", ft.Description)
	fmt.Printf("Extension:      .%s\n", ft.Extension)
	fmt.Printf("MIME Type:      %s\n", ft.MIMEType)
	fmt.Printf("Category:       %s\n", strings.Title(ft.Category))
	fmt.Printf("Confidence:     %d%%\n", ft.Confidence)

	if ft.DeclaredExt != "" && ft.DeclaredExt != ft.Extension && !ft.IsSpoofed {
		fmt.Printf("Declared Ext:   .%s (compatible)\n", ft.DeclaredExt)
	}

	// Additional warnings
	if ft.IsDangerous() {
		fmt.Println()
		fmt.Println("⚡ This is an executable or script file - exercise caution!")
	}

	if identifyVerbose {
		fmt.Println()
		fmt.Println("ANALYSIS:")
		if ft.Category == "executable" {
			fmt.Println("  - This file can execute code on your system")
			fmt.Println("  - Only run files from trusted sources")
		}
		if ft.Category == "script" {
			fmt.Println("  - This script can execute commands")
			fmt.Println("  - Review contents before execution")
		}
		if ft.Category == "archive" {
			fmt.Println("  - Archive files can contain multiple files")
			fmt.Println("  - Scan contents after extraction")
		}
		if ft.IsSpoofed {
			fmt.Println("  - File extension does not match actual content")
			fmt.Println("  - Common malware technique to evade detection")
			fmt.Println("  - DO NOT OPEN unless you trust the source")
		}
	}

	fmt.Println(strings.Repeat("=", 70))
	fmt.Println()
}

func printIdentifyJSON(paths []string, results []*filetype.FileType) error {
	type FileResult struct {
		Path     string            `json:"path"`
		FileType *filetype.FileType `json:"file_type"`
	}

	output := make([]FileResult, len(results))
	for i, result := range results {
		output[i] = FileResult{
			Path:     paths[i],
			FileType: result,
		}
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(map[string]interface{}{
		"total":   len(output),
		"results": output,
	})
}

func printIdentifySummary(results []*filetype.FileType) {
	spoofed := 0
	dangerous := 0
	critical := 0

	categories := make(map[string]int)

	for _, ft := range results {
		if ft.IsSpoofed {
			spoofed++
		}
		if ft.IsDangerous() {
			dangerous++
		}
		if ft.GetRiskLevel() == "CRITICAL" {
			critical++
		}
		categories[ft.Category]++
	}

	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("IDENTIFICATION SUMMARY")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Total files analyzed:     %d\n", len(results))
	fmt.Printf("Spoofed files detected:   %d\n", spoofed)
	fmt.Printf("Dangerous files:          %d\n", dangerous)
	fmt.Printf("Critical risk files:      %d\n", critical)

	if len(categories) > 0 {
		fmt.Println("\nFile Categories:")
		for cat, count := range categories {
			fmt.Printf("  - %-15s: %d\n", strings.Title(cat), count)
		}
	}

	if critical > 0 {
		fmt.Println("\n⚠️  CRITICAL: Spoofed executable files detected!")
		fmt.Println("   These files should be treated as highly suspicious.")
	} else if spoofed > 0 {
		fmt.Println("\n⚠️  WARNING: File type spoofing detected!")
	}

	fmt.Println(strings.Repeat("=", 70))
}
