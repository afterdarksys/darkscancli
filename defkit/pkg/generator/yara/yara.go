package yara

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/afterdarksys/defkit/pkg/analyzer"
)

// Rule represents a YARA rule
type Rule struct {
	Name        string            `json:"name"`
	Tags        []string          `json:"tags"`
	Meta        map[string]string `json:"meta"`
	Strings     []RuleString      `json:"strings"`
	Condition   string            `json:"condition"`
	Description string            `json:"description,omitempty"`
}

// RuleString represents a string definition in a YARA rule
type RuleString struct {
	Identifier string `json:"identifier"` // $str1, $hex1, etc.
	Type       string `json:"type"`       // text, hex, regex
	Value      string `json:"value"`
	Modifiers  string `json:"modifiers,omitempty"` // ascii, wide, nocase, etc.
}

// Generator generates YARA rules
type Generator struct {
	author string
}

// New creates a new YARA rule generator
func New(author string) *Generator {
	if author == "" {
		author = "defkit"
	}
	return &Generator{author: author}
}

// Generate generates a comprehensive YARA rule from analysis
func (g *Generator) Generate(analysis *analyzer.Analysis, name string) (*Rule, error) {
	rule := &Rule{
		Name: sanitizeName(name),
		Meta: make(map[string]string),
	}

	// Add metadata
	rule.Meta["author"] = g.author
	rule.Meta["date"] = time.Now().Format("2006-01-02")
	rule.Meta["version"] = "1.0"

	if analysis.Hashes != nil {
		rule.Meta["md5"] = analysis.Hashes.MD5
		rule.Meta["sha256"] = analysis.Hashes.SHA256
	}

	if analysis.Metadata.Description != "" {
		rule.Meta["description"] = analysis.Metadata.Description
	}

	if analysis.Metadata.Family != "" {
		rule.Meta["family"] = analysis.Metadata.Family
		rule.Tags = append(rule.Tags, analysis.Metadata.Family)
	}

	if analysis.Metadata.Severity != "" {
		rule.Meta["severity"] = analysis.Metadata.Severity
	}

	// Add general tags
	if analysis.Sample != nil {
		rule.Tags = append(rule.Tags, string(analysis.Sample.Type))
	}

	for _, tag := range analysis.Metadata.Tags {
		if !containsString(rule.Tags, tag) {
			rule.Tags = append(rule.Tags, tag)
		}
	}

	// Generate string definitions
	g.generateStrings(analysis, rule)

	// Generate condition
	rule.Condition = g.generateCondition(rule)

	if rule.Condition == "" {
		return nil, fmt.Errorf("failed to generate valid condition")
	}

	return rule, nil
}

// generateStrings generates string definitions from analysis
func (g *Generator) generateStrings(analysis *analyzer.Analysis, rule *Rule) {
	stringCount := 0
	hexCount := 0

	// Add interesting text strings
	textStrings := analysis.GetUniqueStrings("")
	for _, str := range textStrings {
		// Skip very common strings
		if len(str) < 6 || isCommonString(str) {
			continue
		}

		// Prioritize URLs, IPs, domains
		strType := classifyString(str)
		if strType == "url" || strType == "ip" || strType == "domain" {
			stringCount++
			rule.Strings = append(rule.Strings, RuleString{
				Identifier: fmt.Sprintf("$str%d", stringCount),
				Type:       "text",
				Value:      str,
				Modifiers:  "ascii wide",
			})

			if stringCount >= 10 {
				break
			}
		}
	}

	// Add general strings if we don't have enough
	if stringCount < 5 {
		for _, str := range textStrings {
			if len(str) >= 8 && !isCommonString(str) {
				stringCount++
				rule.Strings = append(rule.Strings, RuleString{
					Identifier: fmt.Sprintf("$str%d", stringCount),
					Type:       "text",
					Value:      str,
					Modifiers:  "ascii wide nocase",
				})

				if stringCount >= 10 {
					break
				}
			}
		}
	}

	// Add hex patterns
	patterns := analysis.GetSignificantPatterns(16)
	for _, p := range patterns {
		if hexCount >= 5 {
			break
		}

		hexCount++
		rule.Strings = append(rule.Strings, RuleString{
			Identifier: fmt.Sprintf("$hex%d", hexCount),
			Type:       "hex",
			Value:      formatHexPattern(p.HexPattern),
		})
	}

	// Add PE-specific patterns
	if analysis.PEInfo != nil {
		g.addPEStrings(analysis, rule, &stringCount)
	}
}

// addPEStrings adds PE-specific string patterns
func (g *Generator) addPEStrings(analysis *analyzer.Analysis, rule *Rule, stringCount *int) {
	// Add suspicious imports as strings
	suspiciousImports := []string{
		"VirtualAlloc",
		"VirtualProtect",
		"WriteProcessMemory",
		"CreateRemoteThread",
		"SetWindowsHookEx",
		"GetAsyncKeyState",
		"URLDownloadToFile",
	}

	for _, imp := range analysis.PEInfo.Imports {
		for _, suspicious := range suspiciousImports {
			if strings.Contains(imp, suspicious) {
				*stringCount++
				rule.Strings = append(rule.Strings, RuleString{
					Identifier: fmt.Sprintf("$api%d", *stringCount),
					Type:       "text",
					Value:      suspicious,
					Modifiers:  "ascii",
				})
			}
		}
	}
}

// generateCondition generates the condition clause
func (g *Generator) generateCondition(rule *Rule) string {
	if len(rule.Strings) == 0 {
		return ""
	}

	var conditions []string

	// Count different string types
	textCount := 0
	hexCount := 0
	apiCount := 0

	for _, str := range rule.Strings {
		if strings.HasPrefix(str.Identifier, "$str") {
			textCount++
		} else if strings.HasPrefix(str.Identifier, "$hex") {
			hexCount++
		} else if strings.HasPrefix(str.Identifier, "$api") {
			apiCount++
		}
	}

	// Build condition based on available strings
	if textCount > 0 && hexCount > 0 {
		// Require at least 2 text strings and 1 hex pattern
		required := 2
		if textCount < 2 {
			required = textCount
		}
		conditions = append(conditions, fmt.Sprintf("%d of ($str*)", required))
		conditions = append(conditions, "1 of ($hex*)")
	} else if textCount > 0 {
		required := 3
		if textCount < 3 {
			required = textCount
		}
		conditions = append(conditions, fmt.Sprintf("%d of ($str*)", required))
	} else if hexCount > 0 {
		required := 2
		if hexCount < 2 {
			required = hexCount
		}
		conditions = append(conditions, fmt.Sprintf("%d of ($hex*)", required))
	}

	// Add API conditions if present
	if apiCount > 0 {
		conditions = append(conditions, "1 of ($api*)")
	}

	// Add filesize condition for reasonable bounds
	conditions = append(conditions, "filesize < 10MB")

	return strings.Join(conditions, " and ")
}

// GeneratePERule generates a PE-specific YARA rule
func (g *Generator) GeneratePERule(analysis *analyzer.Analysis, name string) (*Rule, error) {
	if analysis.PEInfo == nil {
		return nil, fmt.Errorf("not a PE file")
	}

	rule := &Rule{
		Name: sanitizeName(name) + "_PE",
		Tags: []string{"pe"},
		Meta: make(map[string]string),
	}

	rule.Meta["author"] = g.author
	rule.Meta["date"] = time.Now().Format("2006-01-02")
	rule.Meta["description"] = "PE-specific detection rule"

	// PE header conditions
	var conditions []string
	conditions = append(conditions, "uint16(0) == 0x5A4D") // MZ header

	// Add section entropy conditions
	highEntropySections := 0
	for _, section := range analysis.PEInfo.Sections {
		if section.Entropy > 7.0 {
			highEntropySections++
		}
	}

	if highEntropySections > 0 {
		rule.Meta["packed"] = "true"
		rule.Tags = append(rule.Tags, "packed")
	}

	// Add import conditions
	if len(analysis.PEInfo.Imports) > 0 {
		stringCount := 0
		for _, imp := range analysis.PEInfo.Imports[:min(5, len(analysis.PEInfo.Imports))] {
			stringCount++
			rule.Strings = append(rule.Strings, RuleString{
				Identifier: fmt.Sprintf("$imp%d", stringCount),
				Type:       "text",
				Value:      imp,
				Modifiers:  "ascii",
			})
		}

		if stringCount > 0 {
			conditions = append(conditions, fmt.Sprintf("2 of ($imp*)"))
		}
	}

	rule.Condition = strings.Join(conditions, " and ")

	return rule, nil
}

// Export exports a YARA rule to a file
func (rule *Rule) Export(path string) error {
	content := rule.String()
	return os.WriteFile(path, []byte(content), 0644)
}

// String formats the rule as YARA syntax
func (rule *Rule) String() string {
	var sb strings.Builder

	// Rule header
	sb.WriteString("rule ")
	sb.WriteString(rule.Name)

	// Tags
	if len(rule.Tags) > 0 {
		sb.WriteString(" : ")
		sb.WriteString(strings.Join(rule.Tags, " "))
	}

	sb.WriteString(" {\n")

	// Meta section
	if len(rule.Meta) > 0 {
		sb.WriteString("    meta:\n")
		for key, value := range rule.Meta {
			sb.WriteString(fmt.Sprintf("        %s = \"%s\"\n", key, escapeString(value)))
		}
	}

	// Strings section
	if len(rule.Strings) > 0 {
		sb.WriteString("    strings:\n")
		for _, str := range rule.Strings {
			sb.WriteString("        ")
			sb.WriteString(str.Identifier)
			sb.WriteString(" = ")

			switch str.Type {
			case "text":
				sb.WriteString(fmt.Sprintf("\"%s\"", escapeString(str.Value)))
			case "hex":
				sb.WriteString(fmt.Sprintf("{ %s }", str.Value))
			case "regex":
				sb.WriteString(fmt.Sprintf("/%s/", str.Value))
			}

			if str.Modifiers != "" {
				sb.WriteString(" ")
				sb.WriteString(str.Modifiers)
			}

			sb.WriteString("\n")
		}
	}

	// Condition section
	sb.WriteString("    condition:\n")
	sb.WriteString("        ")
	sb.WriteString(rule.Condition)
	sb.WriteString("\n")

	sb.WriteString("}\n")

	return sb.String()
}

// Helper functions

func sanitizeName(name string) string {
	// YARA rule names must start with letter and contain only alphanumeric + underscore
	name = strings.ReplaceAll(name, "-", "_")
	name = strings.ReplaceAll(name, ".", "_")
	name = strings.ReplaceAll(name, " ", "_")

	// Ensure starts with letter
	if len(name) > 0 && (name[0] >= '0' && name[0] <= '9') {
		name = "rule_" + name
	}

	return name
}

func formatHexPattern(hex string) string {
	// Format as space-separated bytes: "4D 5A 90 00"
	var formatted strings.Builder
	for i := 0; i < len(hex); i += 2 {
		if i > 0 {
			formatted.WriteString(" ")
		}
		formatted.WriteString(strings.ToUpper(hex[i : i+2]))
	}
	return formatted.String()
}

func escapeString(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")
	return s
}

func isCommonString(s string) bool {
	common := []string{
		"http", "www", "com", "exe", "dll", "sys",
		"windows", "system", "program", "microsoft",
		"kernel32", "user32", "ntdll",
	}

	lower := strings.ToLower(s)
	for _, c := range common {
		if lower == c {
			return true
		}
	}

	return false
}

func classifyString(s string) string {
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return "url"
	}
	if strings.Contains(s, ".") && len(s) > 7 {
		parts := strings.Split(s, ".")
		if len(parts) >= 2 {
			return "domain"
		}
	}
	return "text"
}

func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
