package stego

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/afterdarksys/darkscan/pkg/scanner"
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
func (e *Engine) Scan(ctx context.Context, path string) (*scanner.ScanResult, error) {
	// Quick check: only scan images
	ext := strings.ToLower(filepath.Ext(path))
	if !e.imageExts[ext] {
		return &scanner.ScanResult{
			FilePath:   path,
			Infected:   false,
			Threats:    []scanner.Threat{},
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
		return &scanner.ScanResult{
			FilePath:   path,
			Infected:   false,
			Threats:    []scanner.Threat{},
			ScanEngine: e.Name(),
			Error:      err,
		}, nil // Don't fail scan if stego check fails
	}

	result := &scanner.ScanResult{
		FilePath:   path,
		Infected:   false,
		Threats:    []scanner.Threat{},
		ScanEngine: e.Name(),
	}

	// Check if suspicious
	if analysis.Suspicious && analysis.Confidence >= e.minConfidence {
		result.Infected = true

		// Create threats from indicators
		for _, indicator := range analysis.Indicators {
			threat := scanner.Threat{
				Name:        fmt.Sprintf("STEGO.%s", strings.ToUpper(indicator.Type)),
				Severity:    indicator.Severity,
				Description: fmt.Sprintf("%s (Confidence: %d)", indicator.Description, indicator.Confidence),
				Engine:      e.Name(),
			}
			result.Threats = append(result.Threats, threat)
		}

		// Add detected tool signatures as threats
		for _, sig := range analysis.Signatures {
			threat := scanner.Threat{
				Name:        fmt.Sprintf("STEGO.Tool.%s", strings.ReplaceAll(sig.Tool, " ", "")),
				Severity:    "high",
				Description: fmt.Sprintf("%s (Confidence: %d, Tool: %s)", sig.Description, sig.Confidence, sig.Tool),
				Engine:      e.Name(),
			}
			result.Threats = append(result.Threats, threat)
		}

		// If no specific threats but overall suspicious, add generic threat
		if len(result.Threats) == 0 {
			result.Threats = append(result.Threats, scanner.Threat{
				Name:        "STEGO.Generic",
				Severity:    "medium",
				Description: fmt.Sprintf("Steganography detected with %d%% confidence", analysis.Confidence),
				Engine:      e.Name(),
			})
		}
	}

	return result, nil
}

func (e *Engine) ScanReader(ctx context.Context, r io.Reader, name string) (*scanner.ScanResult, error) {
	return scanner.ScanReaderToTemp(ctx, r, name, e.Scan)
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
