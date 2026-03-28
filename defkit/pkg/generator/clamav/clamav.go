package clamav

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/afterdarktech/defkit/pkg/analyzer"
)

// SignatureType represents ClamAV signature format
type SignatureType string

const (
	TypeHDB SignatureType = "hdb" // MD5 hash signatures
	TypeHSB SignatureType = "hsb" // SHA1/SHA256 hash signatures
	TypeNDB SignatureType = "ndb" // Extended signatures
	TypeLDB SignatureType = "ldb" // Logical signatures
	TypePDB SignatureType = "pdb" // PE section signatures
)

// Signature represents a ClamAV signature
type Signature struct {
	Type        SignatureType `json:"type"`
	Name        string        `json:"name"`
	Content     string        `json:"content"`
	Target      string        `json:"target,omitempty"`
	Description string        `json:"description,omitempty"`
}

// Generator generates ClamAV signatures
type Generator struct {
	version string
}

// New creates a new ClamAV signature generator
func New() *Generator {
	return &Generator{
		version: "1",
	}
}

// GenerateHDB generates hash-based signature (MD5)
func (g *Generator) GenerateHDB(analysis *analyzer.Analysis, name string) (*Signature, error) {
	if analysis.Hashes == nil {
		return nil, fmt.Errorf("no hash data available")
	}

	// HDB format: hash:size:malware_name
	content := fmt.Sprintf("%s:%d:%s",
		analysis.Hashes.MD5,
		analysis.Hashes.Size,
		name,
	)

	return &Signature{
		Type:        TypeHDB,
		Name:        name,
		Content:     content,
		Description: "MD5 hash signature",
	}, nil
}

// GenerateHSB generates SHA256 hash-based signature
func (g *Generator) GenerateHSB(analysis *analyzer.Analysis, name string) (*Signature, error) {
	if analysis.Hashes == nil {
		return nil, fmt.Errorf("no hash data available")
	}

	// HSB format: hash:size:malware_name
	content := fmt.Sprintf("%s:%d:%s",
		analysis.Hashes.SHA256,
		analysis.Hashes.Size,
		name,
	)

	return &Signature{
		Type:        TypeHSB,
		Name:        name,
		Content:     content,
		Description: "SHA256 hash signature",
	}, nil
}

// GenerateNDB generates extended signature with hex pattern
func (g *Generator) GenerateNDB(analysis *analyzer.Analysis, name string, minLength int) ([]*Signature, error) {
	var signatures []*Signature

	// Get significant patterns (not too high entropy, not too low)
	patterns := analysis.GetSignificantPatterns(minLength)

	if len(patterns) == 0 {
		return nil, fmt.Errorf("no suitable patterns found")
	}

	// Take top patterns
	maxSigs := 5
	if len(patterns) > maxSigs {
		patterns = patterns[:maxSigs]
	}

	for i, p := range patterns {
		// NDB format: Malware.Name:TargetType:Offset:HexSignature
		// TargetType: 0=any, 1=PE, 2=OLE2, 3=HTML, 4=Mail, 5=Graphics, 6=ELF
		targetType := "0" // any
		if analysis.Sample != nil {
			switch analysis.Sample.Type {
			case "pe":
				targetType = "1"
			case "elf":
				targetType = "6"
			}
		}

		content := fmt.Sprintf("%s:%s:%d:%s",
			fmt.Sprintf("%s.Pattern%d", name, i+1),
			targetType,
			p.Offset,
			p.HexPattern,
		)

		sig := &Signature{
			Type:        TypeNDB,
			Name:        fmt.Sprintf("%s.Pattern%d", name, i+1),
			Content:     content,
			Description: fmt.Sprintf("Pattern signature at offset %d", p.Offset),
		}

		signatures = append(signatures, sig)
	}

	return signatures, nil
}

// GenerateLDB generates logical signature with multiple patterns
func (g *Generator) GenerateLDB(analysis *analyzer.Analysis, name string) (*Signature, error) {
	patterns := analysis.GetSignificantPatterns(16)

	if len(patterns) < 2 {
		return nil, fmt.Errorf("need at least 2 patterns for logical signature")
	}

	// Take top 3 patterns
	if len(patterns) > 3 {
		patterns = patterns[:3]
	}

	// LDB format: SignatureName;TargetDescriptionBlock;LogicalExpression;Subsig0;Subsig1;...
	// TargetDescriptionBlock: Target:Offset:MaxShift
	target := "0" // any file
	if analysis.Sample != nil {
		switch analysis.Sample.Type {
		case "pe":
			target = "1" // PE
		case "elf":
			target = "6" // ELF
		}
	}

	targetBlock := fmt.Sprintf("%s:*:*", target)

	// Logical expression - all patterns must match
	var expr strings.Builder
	for i := range patterns {
		if i > 0 {
			expr.WriteString("&")
		}
		expr.WriteString(fmt.Sprintf("%d", i))
	}

	// Build subsignatures
	var subsigs []string
	for _, p := range patterns {
		subsigs = append(subsigs, p.HexPattern)
	}

	content := fmt.Sprintf("%s;%s;%s;%s",
		name,
		targetBlock,
		expr.String(),
		strings.Join(subsigs, ";"),
	)

	return &Signature{
		Type:        TypeLDB,
		Name:        name,
		Content:     content,
		Description: "Logical signature with multiple patterns",
	}, nil
}

// GeneratePDB generates PE section-based signature
func (g *Generator) GeneratePDB(analysis *analyzer.Analysis, name string) ([]*Signature, error) {
	if analysis.PEInfo == nil {
		return nil, fmt.Errorf("not a PE file")
	}

	var signatures []*Signature

	// Find sections with moderate entropy (not packed, but unique)
	for i, section := range analysis.PEInfo.Sections {
		if section.Entropy > 4.0 && section.Entropy < 7.0 {
			// PDB format: SignatureName:SectionNumber:HexSignature
			// We'll use a simplified format
			content := fmt.Sprintf("%s.Section%d:%d:%s",
				name,
				i,
				i,
				fmt.Sprintf("%x", section.Name), // Use section name as identifier
			)

			sig := &Signature{
				Type:        TypePDB,
				Name:        fmt.Sprintf("%s.Section%d", name, i),
				Content:     content,
				Description: fmt.Sprintf("PE section signature: %s", section.Name),
			}

			signatures = append(signatures, sig)
		}
	}

	if len(signatures) == 0 {
		return nil, fmt.Errorf("no suitable PE sections found")
	}

	return signatures, nil
}

// GenerateAll generates all signature types
func (g *Generator) GenerateAll(analysis *analyzer.Analysis, name string) (map[SignatureType][]*Signature, error) {
	results := make(map[SignatureType][]*Signature)

	// HDB
	if hdb, err := g.GenerateHDB(analysis, name); err == nil {
		results[TypeHDB] = []*Signature{hdb}
	}

	// HSB
	if hsb, err := g.GenerateHSB(analysis, name); err == nil {
		results[TypeHSB] = []*Signature{hsb}
	}

	// NDB
	if ndb, err := g.GenerateNDB(analysis, name, 16); err == nil {
		results[TypeNDB] = ndb
	}

	// LDB
	if ldb, err := g.GenerateLDB(analysis, name); err == nil {
		results[TypeLDB] = []*Signature{ldb}
	}

	// PDB (only for PE files)
	if analysis.Sample != nil && analysis.Sample.Type == "pe" {
		if pdb, err := g.GeneratePDB(analysis, name); err == nil {
			results[TypePDB] = pdb
		}
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("failed to generate any signatures")
	}

	return results, nil
}

// WriteSignatures writes signatures to files
func WriteSignatures(signatures map[SignatureType][]*Signature, outputDir string) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	for sigType, sigs := range signatures {
		filename := filepath.Join(outputDir, fmt.Sprintf("custom.%s", sigType))

		var content strings.Builder
		for _, sig := range sigs {
			content.WriteString(sig.Content)
			content.WriteString("\n")
		}

		if err := os.WriteFile(filename, []byte(content.String()), 0644); err != nil {
			return fmt.Errorf("write %s: %w", sigType, err)
		}
	}

	return nil
}

// Database represents a ClamAV database file
type Database struct {
	Name       string                           `json:"name"`
	Version    int                              `json:"version"`
	Builder    string                           `json:"builder"`
	BuildTime  time.Time                        `json:"build_time"`
	Signatures map[SignatureType][]*Signature   `json:"signatures"`
}

// NewDatabase creates a new database
func NewDatabase(name string) *Database {
	return &Database{
		Name:       name,
		Version:    1,
		Builder:    "defkit",
		BuildTime:  time.Now(),
		Signatures: make(map[SignatureType][]*Signature),
	}
}

// AddSignatures adds signatures to the database
func (db *Database) AddSignatures(sigType SignatureType, sigs []*Signature) {
	db.Signatures[sigType] = append(db.Signatures[sigType], sigs...)
}

// Export exports database to directory with separate files per type
func (db *Database) Export(outputDir string) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	// Write main database file (metadata)
	infoPath := filepath.Join(outputDir, "database.info")
	info := fmt.Sprintf("Name: %s\nVersion: %d\nBuilder: %s\nBuild Time: %s\n",
		db.Name,
		db.Version,
		db.Builder,
		db.BuildTime.Format(time.RFC3339),
	)

	if err := os.WriteFile(infoPath, []byte(info), 0644); err != nil {
		return fmt.Errorf("write database info: %w", err)
	}

	// Write signature files
	return WriteSignatures(db.Signatures, outputDir)
}

// Count returns total signature count
func (db *Database) Count() int {
	count := 0
	for _, sigs := range db.Signatures {
		count += len(sigs)
	}
	return count
}
