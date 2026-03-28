package heuristics

import (
	"context"

	"github.com/afterdarksys/darkscan/pkg/forensics"
	"github.com/afterdarksys/darkscan/pkg/scanner"
)

type Engine struct {
	analyzer *forensics.Analyzer
}

func New() *Engine {
	return &Engine{
		analyzer: forensics.NewAnalyzer(100),
	}
}

func (e *Engine) Name() string {
	return "Heuristics"
}

func (e *Engine) Scan(ctx context.Context, path string) (*scanner.ScanResult, error) {
	feats, err := e.analyzer.Analyze(path)
	if err != nil {
		// Not a file we can analyze
		return nil, err
	}

	score := 0
	var desc []string

	if feats.Entropy > 7.0 {
		score += 30
		desc = append(desc, "High Entropy (Potential Packing/Encryption)")
	}

	if feats.HasInjection {
		score += 40
		desc = append(desc, "Process Injection API usage detected")
	}

	if feats.HasEvasion {
		score += 20
		desc = append(desc, "Sandbox/Debug evasion API usage detected")
	}

	if feats.HasExecutableStack {
		score += 50
		desc = append(desc, "Executable Stack detected (Exploitation artifact)")
	}

	threat := scanner.Threat{
		Name:        "Heuristic.Suspicious",
		Engine:      "Heuristics",
	}

	for _, d := range desc {
		threat.Description += d + "; "
	}

	infected := false
	var threats []scanner.Threat

	if score >= 60 {
		infected = true
		threat.Severity = "High"
		threats = append(threats, threat)
	} else if score >= 30 {
		threat.Severity = "Medium" // Note: not marked infected but reported
		threats = append(threats, threat)
	}

	return &scanner.ScanResult{
		FilePath:   path,
		Infected:   infected,
		Threats:    threats,
		ScanEngine: e.Name(),
	}, nil
}

func (e *Engine) Update(ctx context.Context) error {
	return nil // No external updates needed
}

func (e *Engine) Close() error {
	return nil
}
