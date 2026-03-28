package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/afterdarksys/darkscan/pkg/forensics"
	"github.com/spf13/cobra"
)

var (
	forensicsOutputFormat string
)

var forensicsCmd = &cobra.Command{
	Use:   "forensics [file]",
	Short: "Extract file metadata and forensic information",
	Long:  `Analyze a file and extract detailed metadata including hashes, entropy, binary structure, and behavioral indicators.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runForensics,
}

func init() {
	forensicsCmd.Flags().StringVarP(&forensicsOutputFormat, "output", "o", "text", "Output format (text, json)")
}

func runForensics(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	analyzer := forensics.NewAnalyzer(100) // 100MB threshold
	features, err := analyzer.Analyze(filePath)
	if err != nil {
		return fmt.Errorf("failed to analyze file: %w", err)
	}

	if forensicsOutputFormat == "json" {
		return printForensicsJSON(features)
	}

	return printForensicsText(features, filePath)
}

func printForensicsJSON(features *forensics.FileFeatures) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(features)
}

func printForensicsText(features *forensics.FileFeatures, filePath string) error {
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("FILE FORENSICS ANALYSIS")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("File: %s\n", filePath)
	fmt.Println(strings.Repeat("-", 70))

	// File Type Identification
	if features.DetectedType != "" {
		fmt.Println("\nFILE TYPE IDENTIFICATION:")
		fmt.Printf("  Detected Type:   %s\n", features.DetectedType)
		fmt.Printf("  MIME Type:       %s\n", features.MIMEType)
		fmt.Printf("  Category:        %s\n", strings.Title(features.FileCategory))
		fmt.Printf("  Confidence:      %d%%\n", features.TypeConfidence)

		// Spoofing detection
		if features.IsSpoofed {
			fmt.Println()
			fmt.Println("  ⚠️  WARNING: FILE TYPE SPOOFING DETECTED!")
			fmt.Printf("  Declared Extension: .%s\n", features.DeclaredExt)
			fmt.Printf("  Actual File Type:   .%s\n", features.ActualType)
			fmt.Println("  This file may be malicious!")
		} else if features.DeclaredExt != "" && features.DeclaredExt != features.DetectedType {
			fmt.Printf("  Declared Ext:    .%s (compatible)\n", features.DeclaredExt)
		}
	}

	// Hashes
	fmt.Println("\nCRYPTOGRAPHIC HASHES:")
	fmt.Printf("  MD5:     %s\n", features.MD5)
	fmt.Printf("  SHA1:    %s\n", features.SHA1)
	fmt.Printf("  SHA256:  %s\n", features.SHA256)

	// File Info
	fmt.Println("\nFILE INFORMATION:")
	fmt.Printf("  Size:    %s\n", formatBytes(features.Size))
	if features.Type != "" {
		fmt.Printf("  Binary Type: %s\n", features.Type)
	}
	fmt.Printf("  Entropy: %.2f\n", features.Entropy)

	// Binary Structure (if available)
	if features.NumSections > 0 || features.NumImports > 0 {
		fmt.Println("\nBINARY STRUCTURE:")
		if features.NumSections > 0 {
			fmt.Printf("  Sections: %d\n", features.NumSections)
		}
		if features.NumImports > 0 {
			fmt.Printf("  Imports:  %d\n", features.NumImports)
		}
		if features.NumExports > 0 {
			fmt.Printf("  Exports:  %d\n", features.NumExports)
		}
		if features.ImpHash != "" {
			fmt.Printf("  ImpHash:  %s\n", features.ImpHash)
		}
	}

	// Behavioral Indicators
	indicators := []string{}
	if features.HasNetworkCalls {
		indicators = append(indicators, "Network Calls")
	}
	if features.HasInjection {
		indicators = append(indicators, "Process Injection")
	}
	if features.HasEvasion {
		indicators = append(indicators, "Anti-Debug/Evasion")
	}
	if features.HasPersistence {
		indicators = append(indicators, "Persistence Mechanisms")
	}
	if features.HasCrypto {
		indicators = append(indicators, "Cryptography APIs")
	}
	if features.HasExecutableStack {
		indicators = append(indicators, "Executable Stack")
	}

	if len(indicators) > 0 {
		fmt.Println("\nBEHAVIORAL INDICATORS:")
		for _, indicator := range indicators {
			fmt.Printf("  - %s\n", indicator)
		}
	} else {
		fmt.Println("\nBEHAVIORAL INDICATORS: None detected")
	}

	// Strings Analysis
	if features.StringsCount > 0 {
		fmt.Println("\nSTRINGS ANALYSIS:")
		fmt.Printf("  Total strings: %d\n", features.StringsCount)
	}

	// Entropy Analysis
	fmt.Println("\nENTROPY ANALYSIS:")
	if features.Entropy > 7.5 {
		fmt.Println("  [HIGH] File has very high entropy - may be packed/encrypted")
	} else if features.Entropy > 7.0 {
		fmt.Println("  [MEDIUM] File has high entropy - possibly compressed")
	} else {
		fmt.Println("  [LOW] File has normal entropy")
	}

	fmt.Println(strings.Repeat("=", 70))
	return nil
}
