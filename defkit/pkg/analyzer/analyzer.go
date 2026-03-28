package analyzer

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/afterdarksys/defkit/internal/hash"
	"github.com/afterdarksys/defkit/internal/pattern"
	"github.com/afterdarksys/defkit/internal/sample"
)

// Analysis contains comprehensive analysis results
type Analysis struct {
	Sample      *sample.Sample    `json:"sample"`
	Hashes      *hash.Hashes      `json:"hashes"`
	Strings     []pattern.String  `json:"strings"`
	Patterns    []pattern.Pattern `json:"patterns"`
	PEInfo      *sample.PEInfo    `json:"pe_info,omitempty"`
	ELFInfo     *sample.ELFInfo   `json:"elf_info,omitempty"`
	MachOInfo   *sample.MachOInfo `json:"macho_info,omitempty"`
	Metadata    Metadata          `json:"metadata"`
}

// Metadata contains analysis metadata
type Metadata struct {
	ThreatName  string   `json:"threat_name,omitempty"`
	Family      string   `json:"family,omitempty"`
	Description string   `json:"description,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	References  []string `json:"references,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// Options configures the analysis
type Options struct {
	ExtractStrings  bool `json:"extract_strings"`
	ExtractPatterns bool `json:"extract_patterns"`
	DeepAnalysis    bool `json:"deep_analysis"`
	MinStringLength int  `json:"min_string_length"`
	MinPatternLength int  `json:"min_pattern_length"`
	MaxPatternLength int  `json:"max_pattern_length"`
}

// DefaultOptions returns default analysis options
func DefaultOptions() Options {
	return Options{
		ExtractStrings:  true,
		ExtractPatterns: true,
		DeepAnalysis:    true,
		MinStringLength: 4,
		MinPatternLength: 8,
		MaxPatternLength: 64,
	}
}

// Analyzer performs malware analysis
type Analyzer struct {
	opts Options
}

// New creates a new analyzer with options
func New(opts Options) *Analyzer {
	return &Analyzer{opts: opts}
}

// Analyze performs comprehensive analysis on a file
func (a *Analyzer) Analyze(path string) (*Analysis, error) {
	analysis := &Analysis{
		Metadata: Metadata{},
	}

	// Identify sample type
	s, err := sample.Identify(path)
	if err != nil {
		return nil, fmt.Errorf("identify sample: %w", err)
	}
	analysis.Sample = s

	// Compute hashes
	hashes, err := hash.ComputeAll(path)
	if err != nil {
		return nil, fmt.Errorf("compute hashes: %w", err)
	}
	analysis.Hashes = hashes

	// Read file data
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	// Extract strings
	if a.opts.ExtractStrings {
		analysis.Strings = pattern.ExtractStrings(data, a.opts.MinStringLength)
	}

	// Extract patterns
	if a.opts.ExtractPatterns {
		analysis.Patterns = pattern.ExtractPatterns(data, a.opts.MinPatternLength, a.opts.MaxPatternLength)
	}

	// Deep analysis based on file type
	if a.opts.DeepAnalysis {
		switch s.Type {
		case sample.TypePE:
			peInfo, err := sample.AnalyzePE(path)
			if err == nil {
				analysis.PEInfo = peInfo
				a.analyzePEBehavior(analysis)
			}
		case sample.TypeELF:
			elfInfo, err := sample.AnalyzeELF(path)
			if err == nil {
				analysis.ELFInfo = elfInfo
			}
		case sample.TypeMachO:
			machoInfo, err := sample.AnalyzeMachO(path)
			if err == nil {
				analysis.MachOInfo = machoInfo
			}
		}
	}

	// Auto-classify based on analysis
	a.classify(analysis)

	return analysis, nil
}

// analyzePEBehavior adds behavioral tags based on PE characteristics
func (a *Analyzer) analyzePEBehavior(analysis *Analysis) {
	if analysis.PEInfo == nil {
		return
	}

	// Check for suspicious imports
	suspiciousAPIs := map[string]string{
		"VirtualAlloc":        "memory-manipulation",
		"VirtualProtect":      "memory-manipulation",
		"WriteProcessMemory":  "process-injection",
		"CreateRemoteThread":  "process-injection",
		"SetWindowsHookEx":    "hooking",
		"GetAsyncKeyState":    "keylogging",
		"URLDownloadToFile":   "downloader",
		"WinExec":             "execution",
		"ShellExecute":        "execution",
		"RegSetValue":         "persistence",
		"CryptEncrypt":        "encryption",
	}

	for _, imp := range analysis.PEInfo.Imports {
		for api, tag := range suspiciousAPIs {
			if contains(imp, api) {
				if !containsString(analysis.Metadata.Tags, tag) {
					analysis.Metadata.Tags = append(analysis.Metadata.Tags, tag)
				}
			}
		}
	}

	// Check for high entropy sections (packed/encrypted)
	for _, section := range analysis.PEInfo.Sections {
		if section.Entropy > 7.0 {
			if !containsString(analysis.Metadata.Tags, "packed") {
				analysis.Metadata.Tags = append(analysis.Metadata.Tags, "packed")
			}
		}
	}
}

// classify attempts to auto-classify the malware
func (a *Analyzer) classify(analysis *Analysis) {
	// Check strings for indicators
	keywords := map[string]string{
		"ransom":     "ransomware",
		"encrypt":    "ransomware",
		"bitcoin":    "ransomware",
		"keylog":     "keylogger",
		"backdoor":   "backdoor",
		"trojan":     "trojan",
		"worm":       "worm",
		"rootkit":    "rootkit",
		"spyware":    "spyware",
		"adware":     "adware",
		"dropper":    "dropper",
		"downloader": "downloader",
	}

	for _, str := range analysis.Strings {
		for keyword, family := range keywords {
			if contains(str.Value, keyword) {
				if analysis.Metadata.Family == "" {
					analysis.Metadata.Family = family
				}
				if !containsString(analysis.Metadata.Tags, family) {
					analysis.Metadata.Tags = append(analysis.Metadata.Tags, family)
				}
			}
		}
	}

	// Severity based on tags
	if len(analysis.Metadata.Tags) >= 5 {
		analysis.Metadata.Severity = "high"
	} else if len(analysis.Metadata.Tags) >= 2 {
		analysis.Metadata.Severity = "medium"
	} else {
		analysis.Metadata.Severity = "low"
	}
}

// Export exports analysis results to JSON
func (a *Analysis) Export(path string) error {
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}

// GetUniqueStrings returns unique strings by type
func (a *Analysis) GetUniqueStrings(strType string) []string {
	seen := make(map[string]bool)
	var unique []string

	for _, str := range a.Strings {
		if strType == "" || str.Type == strType {
			if !seen[str.Value] {
				seen[str.Value] = true
				unique = append(unique, str.Value)
			}
		}
	}

	return unique
}

// GetHighEntropyPatterns returns patterns from high entropy sections
func (a *Analysis) GetHighEntropyPatterns() []pattern.Pattern {
	var highEntropy []pattern.Pattern

	for _, p := range a.Patterns {
		if p.Entropy > 7.0 {
			highEntropy = append(highEntropy, p)
		}
	}

	return highEntropy
}

// GetSignificantPatterns returns patterns suitable for signatures
func (a *Analysis) GetSignificantPatterns(minLength int) []pattern.Pattern {
	var significant []pattern.Pattern

	for _, p := range a.Patterns {
		// Avoid high entropy (packed/encrypted) and very low entropy (zeros)
		if p.Entropy > 3.0 && p.Entropy < 7.0 && p.Length >= minLength {
			significant = append(significant, p)
		}
	}

	return significant
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if toLower(s[i+j]) != toLower(substr[j]) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func toLower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
