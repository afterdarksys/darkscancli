package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/afterdarktech/defkit/pkg/analyzer"
	"github.com/afterdarktech/defkit/pkg/generator/capa"
	"github.com/afterdarktech/defkit/pkg/generator/clamav"
	"github.com/afterdarktech/defkit/pkg/generator/yara"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "analyze":
		analyzeCommand()
	case "generate":
		generateCommand()
	case "version":
		fmt.Printf("defkit version %s\n", version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`defkit - Virus Definition Kit v%s

USAGE:
    defkit <command> [options]

COMMANDS:
    analyze     Analyze a malware sample
    generate    Generate signatures from analysis
    version     Show version information
    help        Show this help message

ANALYZE COMMAND:
    defkit analyze [options] <file>

    Options:
        -o, --output <dir>      Output directory for analysis results
        -f, --format <format>   Output format: json, text (default: json)
        --no-strings            Skip string extraction
        --no-patterns           Skip pattern extraction
        --min-string <n>        Minimum string length (default: 4)

    Examples:
        defkit analyze malware.exe
        defkit analyze --output analysis/ malware.exe
        defkit analyze --format text malware.exe

GENERATE COMMAND:
    defkit generate [options] <file-or-analysis>

    Options:
        -o, --output <dir>      Output directory (default: ./signatures)
        -n, --name <name>       Threat name (required)
        -f, --format <fmt>      Format: all, clamav, yara, capa (default: all)
        --clamav-type <type>    ClamAV type: all, hdb, ndb, ldb (default: all)
        --author <name>         Author name (default: defkit)
        -d, --description <txt> Threat description
        --family <name>         Malware family
        --severity <level>      Severity: low, medium, high

    Examples:
        defkit generate --name Trojan.Generic malware.exe
        defkit generate --format yara --name MyRule malware.exe
        defkit generate --name Ransom.A --family ransomware malware.exe

EXAMPLES:
    # Analyze and generate all signature types
    defkit analyze malware.exe -o analysis/
    defkit generate analysis/malware.json --name Trojan.Win32.Agent

    # Quick generation from sample
    defkit generate malware.exe --name Backdoor.Generic --format yara

For more information, visit: https://github.com/afterdarktech/defkit
`, version)
}

func analyzeCommand() {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	output := fs.String("o", "", "Output directory")
	outputAlt := fs.String("output", "", "Output directory")
	format := fs.String("f", "json", "Output format")
	formatAlt := fs.String("format", "json", "Output format")
	noStrings := fs.Bool("no-strings", false, "Skip string extraction")
	noPatterns := fs.Bool("no-patterns", false, "Skip pattern extraction")
	minString := fs.Int("min-string", 4, "Minimum string length")

	fs.Parse(os.Args[2:])

	if fs.NArg() == 0 {
		fmt.Println("Error: file path required")
		fmt.Println("\nUsage: defkit analyze [options] <file>")
		os.Exit(1)
	}

	filePath := fs.Arg(0)

	// Determine output dir
	outDir := *output
	if outDir == "" {
		outDir = *outputAlt
	}

	// Determine format
	outputFormat := *format
	if outputFormat == "" {
		outputFormat = *formatAlt
	}

	// Create analyzer
	opts := analyzer.DefaultOptions()
	opts.ExtractStrings = !*noStrings
	opts.ExtractPatterns = !*noPatterns
	opts.MinStringLength = *minString

	a := analyzer.New(opts)

	// Analyze
	fmt.Printf("Analyzing: %s\n", filePath)
	analysis, err := a.Analyze(filePath)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Print results
	printAnalysis(analysis, outputFormat)

	// Save to file if output dir specified
	if outDir != "" {
		if err := os.MkdirAll(outDir, 0755); err != nil {
			fmt.Printf("Error creating output directory: %v\n", err)
			os.Exit(1)
		}

		basename := filepath.Base(filePath)
		outFile := filepath.Join(outDir, basename+".json")

		if err := analysis.Export(outFile); err != nil {
			fmt.Printf("Error saving analysis: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("\nAnalysis saved to: %s\n", outFile)
	}
}

func generateCommand() {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	output := fs.String("o", "./signatures", "Output directory")
	outputAlt := fs.String("output", "./signatures", "Output directory")
	name := fs.String("n", "", "Threat name (required)")
	nameAlt := fs.String("name", "", "Threat name (required)")
	format := fs.String("f", "all", "Format: all, clamav, yara, capa")
	formatAlt := fs.String("format", "all", "Format")
	clamavType := fs.String("clamav-type", "all", "ClamAV type: all, hdb, ndb, ldb")
	author := fs.String("author", "defkit", "Author name")
	description := fs.String("d", "", "Threat description")
	descriptionAlt := fs.String("description", "", "Threat description")
	family := fs.String("family", "", "Malware family")
	severity := fs.String("severity", "", "Severity: low, medium, high")

	fs.Parse(os.Args[2:])

	if fs.NArg() == 0 {
		fmt.Println("Error: file or analysis path required")
		fmt.Println("\nUsage: defkit generate [options] <file-or-analysis>")
		os.Exit(1)
	}

	inputPath := fs.Arg(0)

	// Get threat name
	threatName := *name
	if threatName == "" {
		threatName = *nameAlt
	}
	if threatName == "" {
		fmt.Println("Error: --name is required")
		os.Exit(1)
	}

	// Get output dir
	outDir := *output
	if outDir == "" {
		outDir = *outputAlt
	}

	// Get format
	outputFormat := *format
	if outputFormat == "" {
		outputFormat = *formatAlt
	}

	// Get description
	desc := *description
	if desc == "" {
		desc = *descriptionAlt
	}

	// Load or create analysis
	var analysis *analyzer.Analysis
	var err error

	if strings.HasSuffix(inputPath, ".json") {
		// Load existing analysis
		analysis, err = loadAnalysis(inputPath)
		if err != nil {
			fmt.Printf("Error loading analysis: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Analyze file
		fmt.Printf("Analyzing: %s\n", inputPath)
		opts := analyzer.DefaultOptions()
		a := analyzer.New(opts)
		analysis, err = a.Analyze(inputPath)
		if err != nil {
			fmt.Printf("Error analyzing file: %v\n", err)
			os.Exit(1)
		}
	}

	// Update metadata
	if desc != "" {
		analysis.Metadata.Description = desc
	}
	if *family != "" {
		analysis.Metadata.Family = *family
	}
	if *severity != "" {
		analysis.Metadata.Severity = *severity
	}

	fmt.Printf("Generating signatures: %s\n", threatName)

	// Generate signatures based on format
	switch outputFormat {
	case "all":
		generateAll(analysis, threatName, outDir, *clamavType, *author)
	case "clamav":
		generateClamAV(analysis, threatName, outDir, *clamavType)
	case "yara":
		generateYARA(analysis, threatName, outDir, *author)
	case "capa":
		generateCAPA(analysis, threatName, outDir, *author)
	default:
		fmt.Printf("Unknown format: %s\n", outputFormat)
		os.Exit(1)
	}

	fmt.Printf("\nSignatures saved to: %s\n", outDir)
}

func generateAll(analysis *analyzer.Analysis, name, outDir, clamavType, author string) {
	fmt.Println("  - Generating ClamAV signatures...")
	generateClamAV(analysis, name, filepath.Join(outDir, "clamav"), clamavType)

	fmt.Println("  - Generating YARA rules...")
	generateYARA(analysis, name, filepath.Join(outDir, "yara"), author)

	fmt.Println("  - Generating CAPA rules...")
	generateCAPA(analysis, name, filepath.Join(outDir, "capa"), author)
}

func generateClamAV(analysis *analyzer.Analysis, name, outDir, sigType string) {
	gen := clamav.New()

	var sigs map[clamav.SignatureType][]*clamav.Signature
	var err error

	if sigType == "all" {
		sigs, err = gen.GenerateAll(analysis, name)
	} else {
		// Generate specific type
		switch sigType {
		case "hdb":
			sig, e := gen.GenerateHDB(analysis, name)
			if e == nil {
				sigs = map[clamav.SignatureType][]*clamav.Signature{
					clamav.TypeHDB: {sig},
				}
			} else {
				err = e
			}
		case "ndb":
			sigList, e := gen.GenerateNDB(analysis, name, 16)
			if e == nil {
				sigs = map[clamav.SignatureType][]*clamav.Signature{
					clamav.TypeNDB: sigList,
				}
			} else {
				err = e
			}
		case "ldb":
			sig, e := gen.GenerateLDB(analysis, name)
			if e == nil {
				sigs = map[clamav.SignatureType][]*clamav.Signature{
					clamav.TypeLDB: {sig},
				}
			} else {
				err = e
			}
		default:
			fmt.Printf("Unknown ClamAV type: %s\n", sigType)
			return
		}
	}

	if err != nil {
		fmt.Printf("Error generating ClamAV signatures: %v\n", err)
		return
	}

	if err := clamav.WriteSignatures(sigs, outDir); err != nil {
		fmt.Printf("Error writing signatures: %v\n", err)
		return
	}

	// Print summary
	total := 0
	for _, sigList := range sigs {
		total += len(sigList)
	}
	fmt.Printf("    Generated %d ClamAV signature(s)\n", total)
}

func generateYARA(analysis *analyzer.Analysis, name, outDir, author string) {
	gen := yara.New(author)

	rule, err := gen.Generate(analysis, name)
	if err != nil {
		fmt.Printf("Error generating YARA rule: %v\n", err)
		return
	}

	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Printf("Error creating output directory: %v\n", err)
		return
	}

	outFile := filepath.Join(outDir, name+".yar")
	if err := rule.Export(outFile); err != nil {
		fmt.Printf("Error writing YARA rule: %v\n", err)
		return
	}

	fmt.Printf("    Generated YARA rule: %s\n", outFile)
}

func generateCAPA(analysis *analyzer.Analysis, name, outDir, author string) {
	gen := capa.New(author)

	rule, err := gen.Generate(analysis, name)
	if err != nil {
		fmt.Printf("Error generating CAPA rule: %v\n", err)
		return
	}

	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Printf("Error creating output directory: %v\n", err)
		return
	}

	// Export as both JSON and YAML
	jsonFile := filepath.Join(outDir, name+".json")
	if err := rule.Export(jsonFile); err != nil {
		fmt.Printf("Error writing CAPA JSON: %v\n", err)
		return
	}

	yamlFile := filepath.Join(outDir, name+".yml")
	if err := rule.ExportYAML(yamlFile); err != nil {
		fmt.Printf("Error writing CAPA YAML: %v\n", err)
		return
	}

	fmt.Printf("    Generated CAPA rule: %s, %s\n", jsonFile, yamlFile)
}

func printAnalysis(analysis *analyzer.Analysis, format string) {
	if format == "json" {
		data, _ := json.MarshalIndent(analysis, "", "  ")
		fmt.Println(string(data))
		return
	}

	// Text format
	fmt.Println("\n=== Analysis Results ===")
	fmt.Printf("\nFile: %s\n", analysis.Sample.Path)
	fmt.Printf("Type: %s\n", analysis.Sample.Type)
	if analysis.Sample.Arch != "" {
		fmt.Printf("Architecture: %s\n", analysis.Sample.Arch)
	}

	fmt.Printf("\nHashes:\n")
	fmt.Printf("  MD5:    %s\n", analysis.Hashes.MD5)
	fmt.Printf("  SHA256: %s\n", analysis.Hashes.SHA256)
	if analysis.Hashes.SSDEEP != "" {
		fmt.Printf("  SSDEEP: %s\n", analysis.Hashes.SSDEEP)
	}

	if len(analysis.Strings) > 0 {
		fmt.Printf("\nStrings: %d found\n", len(analysis.Strings))
		// Show first 10
		count := 10
		if len(analysis.Strings) < count {
			count = len(analysis.Strings)
		}
		for i := 0; i < count; i++ {
			str := analysis.Strings[i]
			fmt.Printf("  [%s] %s\n", str.Type, str.Value)
		}
	}

	if len(analysis.Patterns) > 0 {
		fmt.Printf("\nPatterns: %d found\n", len(analysis.Patterns))
	}

	if analysis.PEInfo != nil {
		fmt.Printf("\nPE Information:\n")
		fmt.Printf("  Machine: %s\n", analysis.PEInfo.Machine)
		fmt.Printf("  Sections: %d\n", len(analysis.PEInfo.Sections))
		fmt.Printf("  Imports: %d\n", len(analysis.PEInfo.Imports))
		fmt.Printf("  Exports: %d\n", len(analysis.PEInfo.Exports))
	}

	if len(analysis.Metadata.Tags) > 0 {
		fmt.Printf("\nTags: %s\n", strings.Join(analysis.Metadata.Tags, ", "))
	}

	if analysis.Metadata.Family != "" {
		fmt.Printf("Family: %s\n", analysis.Metadata.Family)
	}

	if analysis.Metadata.Severity != "" {
		fmt.Printf("Severity: %s\n", analysis.Metadata.Severity)
	}
}

func loadAnalysis(path string) (*analyzer.Analysis, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var analysis analyzer.Analysis
	if err := json.Unmarshal(data, &analysis); err != nil {
		return nil, err
	}

	return &analysis, nil
}
