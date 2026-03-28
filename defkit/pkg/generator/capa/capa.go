package capa

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/afterdarksys/defkit/pkg/analyzer"
)

// Rule represents a CAPA rule for behavioral detection
type Rule struct {
	Name        string                 `json:"name"`
	Namespace   string                 `json:"namespace,omitempty"`
	Authors     []string               `json:"authors,omitempty"`
	Scope       string                 `json:"scope"` // file, function, basic block
	ATT         *ATTMapping            `json:"att,omitempty"`
	MBC         []string               `json:"mbc,omitempty"`
	References  []string               `json:"references,omitempty"`
	Examples    []string               `json:"examples,omitempty"`
	Description string                 `json:"description,omitempty"`
	Features    []Feature              `json:"features"`
	Meta        map[string]interface{} `json:"meta,omitempty"`
}

// ATTMapping represents ATT&CK framework mapping
type ATTMapping struct {
	Tactic    string   `json:"tactic"`
	Technique string   `json:"technique"`
	Subtechnique string `json:"subtechnique,omitempty"`
	ID        string   `json:"id"`
}

// Feature represents a capability feature
type Feature struct {
	Type        string      `json:"type"` // api, string, number, bytes, characteristic
	Value       interface{} `json:"value,omitempty"`
	Description string      `json:"description,omitempty"`
}

// Generator generates CAPA rules
type Generator struct {
	author string
}

// New creates a new CAPA rule generator
func New(author string) *Generator {
	if author == "" {
		author = "defkit"
	}
	return &Generator{author: author}
}

// Generate generates a CAPA rule from analysis
func (g *Generator) Generate(analysis *analyzer.Analysis, name string) (*Rule, error) {
	rule := &Rule{
		Name:    name,
		Scope:   "file",
		Authors: []string{g.author},
		Meta:    make(map[string]interface{}),
	}

	// Set namespace based on family
	if analysis.Metadata.Family != "" {
		rule.Namespace = fmt.Sprintf("malware/%s", analysis.Metadata.Family)
	} else {
		rule.Namespace = "malware/unknown"
	}

	// Add description
	if analysis.Metadata.Description != "" {
		rule.Description = analysis.Metadata.Description
	}

	// Add ATT&CK mapping based on detected capabilities
	g.mapATTACK(analysis, rule)

	// Generate features from analysis
	g.generateFeatures(analysis, rule)

	// Add examples
	if analysis.Hashes != nil {
		rule.Examples = []string{analysis.Hashes.SHA256}
	}

	if len(rule.Features) == 0 {
		return nil, fmt.Errorf("no features generated")
	}

	return rule, nil
}

// mapATTACK maps detected behaviors to ATT&CK framework
func (g *Generator) mapATTACK(analysis *analyzer.Analysis, rule *Rule) {
	// Map based on tags
	for _, tag := range analysis.Metadata.Tags {
		switch tag {
		case "process-injection":
			rule.ATT = &ATTMapping{
				Tactic:    "Defense Evasion",
				Technique: "Process Injection",
				ID:        "T1055",
			}
			rule.MBC = append(rule.MBC, "Defense Evasion::Process Injection [E1055]")

		case "keylogging":
			rule.ATT = &ATTMapping{
				Tactic:    "Collection",
				Technique: "Input Capture",
				Subtechnique: "Keylogging",
				ID:        "T1056.001",
			}
			rule.MBC = append(rule.MBC, "Collection::Input Capture::Keylogging [E1056.001]")

		case "persistence":
			rule.ATT = &ATTMapping{
				Tactic:    "Persistence",
				Technique: "Registry Run Keys / Startup Folder",
				ID:        "T1547",
			}
			rule.MBC = append(rule.MBC, "Persistence::Registry Run Keys [E1547]")

		case "downloader":
			rule.ATT = &ATTMapping{
				Tactic:    "Command and Control",
				Technique: "Ingress Tool Transfer",
				ID:        "T1105",
			}
			rule.MBC = append(rule.MBC, "Command and Control::Ingress Tool Transfer [E1105]")

		case "ransomware":
			rule.ATT = &ATTMapping{
				Tactic:    "Impact",
				Technique: "Data Encrypted for Impact",
				ID:        "T1486",
			}
			rule.MBC = append(rule.MBC, "Impact::Data Encrypted for Impact [E1486]")

		case "hooking":
			rule.ATT = &ATTMapping{
				Tactic:    "Credential Access",
				Technique: "Hooking",
				ID:        "T1179",
			}
			rule.MBC = append(rule.MBC, "Credential Access::Hooking [E1179]")
		}

		// Only set first match
		if rule.ATT != nil {
			break
		}
	}
}

// generateFeatures generates capability features
func (g *Generator) generateFeatures(analysis *analyzer.Analysis, rule *Rule) {
	// Add API features from PE imports
	if analysis.PEInfo != nil {
		g.addAPIFeatures(analysis, rule)
	}

	// Add string features
	g.addStringFeatures(analysis, rule)

	// Add characteristic features
	g.addCharacteristics(analysis, rule)
}

// addAPIFeatures adds API call features
func (g *Generator) addAPIFeatures(analysis *analyzer.Analysis, rule *Rule) {
	suspiciousAPIs := map[string]string{
		"VirtualAlloc":        "allocate memory",
		"VirtualProtect":      "change memory permissions",
		"WriteProcessMemory":  "write to remote process",
		"CreateRemoteThread":  "create remote thread",
		"SetWindowsHookEx":    "install hook",
		"GetAsyncKeyState":    "capture keystrokes",
		"URLDownloadToFile":   "download file",
		"WinExec":             "execute command",
		"ShellExecute":        "execute command",
		"RegSetValue":         "modify registry",
		"CryptEncrypt":        "encrypt data",
		"CryptDecrypt":        "decrypt data",
		"InternetOpen":        "network communication",
		"InternetConnect":     "network communication",
	}

	for _, imp := range analysis.PEInfo.Imports {
		for api, desc := range suspiciousAPIs {
			if strings.Contains(imp, api) {
				rule.Features = append(rule.Features, Feature{
					Type:        "api",
					Value:       api,
					Description: desc,
				})
			}
		}
	}
}

// addStringFeatures adds string-based features
func (g *Generator) addStringFeatures(analysis *analyzer.Analysis, rule *Rule) {
	// Get URLs
	urls := analysis.GetUniqueStrings("url")
	for _, url := range urls {
		rule.Features = append(rule.Features, Feature{
			Type:        "string",
			Value:       url,
			Description: "network URL",
		})
	}

	// Get IPs
	ips := analysis.GetUniqueStrings("ip")
	for _, ip := range ips {
		rule.Features = append(rule.Features, Feature{
			Type:        "string",
			Value:       ip,
			Description: "IP address",
		})
	}

	// Get domains
	domains := analysis.GetUniqueStrings("domain")
	for _, domain := range domains {
		rule.Features = append(rule.Features, Feature{
			Type:        "string",
			Value:       domain,
			Description: "domain name",
		})
	}

	// Look for ransomware-related strings
	ransomwareKeywords := []string{"ransom", "bitcoin", "decrypt", "encrypt", "payment"}
	for _, str := range analysis.Strings {
		lower := strings.ToLower(str.Value)
		for _, keyword := range ransomwareKeywords {
			if strings.Contains(lower, keyword) {
				rule.Features = append(rule.Features, Feature{
					Type:        "string",
					Value:       str.Value,
					Description: "ransomware indicator",
				})
				break
			}
		}
	}
}

// addCharacteristics adds file characteristics
func (g *Generator) addCharacteristics(analysis *analyzer.Analysis, rule *Rule) {
	// Check for packing
	if analysis.PEInfo != nil {
		for _, section := range analysis.PEInfo.Sections {
			if section.Entropy > 7.0 {
				rule.Features = append(rule.Features, Feature{
					Type:        "characteristic",
					Value:       "packed",
					Description: "high entropy section indicates packing",
				})
				break
			}
		}
	}

	// Add file type
	if analysis.Sample != nil {
		rule.Features = append(rule.Features, Feature{
			Type:        "characteristic",
			Value:       "format:" + string(analysis.Sample.Type),
			Description: "file format",
		})
	}
}

// GenerateBehavioralRule generates a rule focused on behaviors
func (g *Generator) GenerateBehavioralRule(analysis *analyzer.Analysis, name string, behavior string) (*Rule, error) {
	rule := &Rule{
		Name:      name + "_behavior",
		Namespace: "behavior/" + behavior,
		Scope:     "file",
		Authors:   []string{g.author},
		Meta:      make(map[string]interface{}),
	}

	rule.Meta["behavior"] = behavior

	// Generate behavior-specific features
	switch behavior {
	case "process-injection":
		rule.Features = []Feature{
			{Type: "api", Value: "VirtualAllocEx", Description: "allocate memory in remote process"},
			{Type: "api", Value: "WriteProcessMemory", Description: "write to remote process"},
			{Type: "api", Value: "CreateRemoteThread", Description: "execute code in remote process"},
		}
		rule.ATT = &ATTMapping{
			Tactic:    "Defense Evasion",
			Technique: "Process Injection",
			ID:        "T1055",
		}

	case "keylogging":
		rule.Features = []Feature{
			{Type: "api", Value: "SetWindowsHookEx", Description: "install keyboard hook"},
			{Type: "api", Value: "GetAsyncKeyState", Description: "read keyboard state"},
		}
		rule.ATT = &ATTMapping{
			Tactic:       "Collection",
			Technique:    "Input Capture",
			Subtechnique: "Keylogging",
			ID:           "T1056.001",
		}

	case "persistence":
		rule.Features = []Feature{
			{Type: "api", Value: "RegSetValue", Description: "modify registry"},
			{Type: "string", Value: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", Description: "autorun registry key"},
		}
		rule.ATT = &ATTMapping{
			Tactic:    "Persistence",
			Technique: "Registry Run Keys",
			ID:        "T1547",
		}

	default:
		return nil, fmt.Errorf("unknown behavior: %s", behavior)
	}

	return rule, nil
}

// Export exports rule to JSON file
func (rule *Rule) Export(path string) error {
	data, err := json.MarshalIndent(rule, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

// ExportYAML exports rule to YAML format (CAPA's native format)
func (rule *Rule) ExportYAML(path string) error {
	// For now, we'll create a simplified YAML representation
	// In production, you'd use a proper YAML library
	var sb strings.Builder

	sb.WriteString("rule:\n")
	sb.WriteString(fmt.Sprintf("  meta:\n"))
	sb.WriteString(fmt.Sprintf("    name: %s\n", rule.Name))
	sb.WriteString(fmt.Sprintf("    namespace: %s\n", rule.Namespace))
	sb.WriteString(fmt.Sprintf("    authors:\n"))
	for _, author := range rule.Authors {
		sb.WriteString(fmt.Sprintf("      - %s\n", author))
	}
	sb.WriteString(fmt.Sprintf("    scope: %s\n", rule.Scope))

	if rule.ATT != nil {
		sb.WriteString("    att&ck:\n")
		sb.WriteString(fmt.Sprintf("      - %s::%s [%s]\n",
			rule.ATT.Tactic, rule.ATT.Technique, rule.ATT.ID))
	}

	if len(rule.MBC) > 0 {
		sb.WriteString("    mbc:\n")
		for _, mbc := range rule.MBC {
			sb.WriteString(fmt.Sprintf("      - %s\n", mbc))
		}
	}

	if len(rule.Examples) > 0 {
		sb.WriteString("    examples:\n")
		for _, example := range rule.Examples {
			sb.WriteString(fmt.Sprintf("      - %s\n", example))
		}
	}

	sb.WriteString("  features:\n")
	for _, feature := range rule.Features {
		sb.WriteString(fmt.Sprintf("    - %s: %v\n", feature.Type, feature.Value))
	}

	return os.WriteFile(path, []byte(sb.String()), 0644)
}
