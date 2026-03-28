package stego

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
)

// Engine implements scanner.Engine interface for steganography detection
type Engine struct {
	analyzer      *Analyzer
	minConfidence int
	imageExts     map[string]bool
}

// NewEngine creates a new steganography detection engine
func NewEngine() *Engine {
	return &Engine{
		analyzer:      NewAnalyzer(),
		minConfidence: 70, // Higher threshold for production use
		imageExts: map[string]bool{
			".jpg":  true,
			".jpeg": true,
			".png":  true,
			".gif":  true,
			".bmp":  true,
		},
	}
}

// SetMinConfidence sets the minimum confidence threshold
func (e *Engine) SetMinConfidence(threshold int) {
	e.minConfidence = threshold
}

// Name returns the engine name
func (e *Engine) Name() string {
	return "Steganography"
}

// Scan scans a file for steganography
func (e *Engine) Scan(ctx context.Context, path string) (*ScanResult, error) {
	// Quick check: only scan images
	ext := strings.ToLower(filepath.Ext(path))
	if !e.imageExts[ext] {
		return &ScanResult{
			FilePath:   path,
			Infected:   false,
			Threats:    []Threat{},
			ScanEngine: e.Name(),
		}, nil
	}

	// Check context
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Analyze file
	analysis, err := e.analyzer.AnalyzeFile(path)
	if err != nil {
		return &ScanResult{
			FilePath:   path,
			Infected:   false,
			Threats:    []Threat{},
			ScanEngine: e.Name(),
			Error:      err,
		}, nil // Don't fail scan if stego check fails
	}

	result := &ScanResult{
		FilePath:   path,
		Infected:   false,
		Threats:    []Threat{},
		ScanEngine: e.Name(),
	}

	// Check if suspicious
	if analysis.Suspicious && analysis.Confidence >= e.minConfidence {
		result.Infected = true

		// Create threats from indicators
		for _, indicator := range analysis.Indicators {
			threat := Threat{
				Name:        fmt.Sprintf("STEGO.%s", strings.ToUpper(indicator.Type)),
				Severity:    indicator.Severity,
				Description: indicator.Description,
				Engine:      e.Name(),
				Confidence:  indicator.Confidence,
				Details:     indicator.Details,
			}
			result.Threats = append(result.Threats, threat)
		}

		// Add detected tool signatures as threats
		for _, sig := range analysis.Signatures {
			threat := Threat{
				Name:        fmt.Sprintf("STEGO.Tool.%s", strings.ReplaceAll(sig.Tool, " ", "")),
				Severity:    "high",
				Description: sig.Description,
				Engine:      e.Name(),
				Confidence:  sig.Confidence,
				Details: map[string]interface{}{
					"tool":    sig.Tool,
					"version": sig.Version,
				},
			}
			result.Threats = append(result.Threats, threat)
		}

		// If no specific threats but overall suspicious, add generic threat
		if len(result.Threats) == 0 {
			result.Threats = append(result.Threats, Threat{
				Name:        "STEGO.Generic",
				Severity:    "medium",
				Description: fmt.Sprintf("Steganography detected with %d%% confidence", analysis.Confidence),
				Engine:      e.Name(),
				Confidence:  analysis.Confidence,
			})
		}
	}

	return result, nil
}

// Update updates steganography signatures (no-op for now)
func (e *Engine) Update(ctx context.Context) error {
	// Steganography detection is heuristic-based, no signatures to update
	return nil
}

// Close closes the engine
func (e *Engine) Close() error {
	return nil
}

// ScanResult matches scanner.ScanResult
type ScanResult struct {
	FilePath   string
	Infected   bool
	Threats    []Threat
	ScanEngine string
	Error      error
}

// Threat matches scanner.Threat with additional stego-specific fields
type Threat struct {
	Name        string
	Severity    string
	Description string
	Engine      string
	Confidence  int
	Details     map[string]interface{}
}
