package yara

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/afterdarktech/darkscan/pkg/scanner"
	"github.com/hillu/go-yara/v4"
)

type Engine struct {
	compiler    *yara.Compiler
	rules       *yara.Rules
	rulesPath   string
	initialized bool
}

func New(rulesPath string) (*Engine, error) {
	if rulesPath == "" {
		return nil, fmt.Errorf("rules path is required")
	}

	e := &Engine{
		rulesPath: rulesPath,
	}

	if err := e.loadRules(); err != nil {
		return nil, fmt.Errorf("failed to load YARA rules: %w", err)
	}

	return e, nil
}

func (e *Engine) loadRules() error {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return fmt.Errorf("failed to create YARA compiler: %w", err)
	}

	info, err := os.Stat(e.rulesPath)
	if err != nil {
		return fmt.Errorf("failed to stat rules path: %w", err)
	}

	if info.IsDir() {
		err = filepath.Walk(e.rulesPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".yar") && !strings.HasSuffix(path, ".yara") {
				return nil
			}

			f, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("failed to open rule file %s: %w", path, err)
			}
			defer f.Close()

			if err := compiler.AddFile(f, filepath.Base(path)); err != nil {
				return fmt.Errorf("failed to add rule file %s: %w", path, err)
			}

			return nil
		})
		if err != nil {
			compiler.Destroy()
			return err
		}
	} else {
		f, err := os.Open(e.rulesPath)
		if err != nil {
			compiler.Destroy()
			return fmt.Errorf("failed to open rule file: %w", err)
		}
		defer f.Close()

		if err := compiler.AddFile(f, filepath.Base(e.rulesPath)); err != nil {
			compiler.Destroy()
			return fmt.Errorf("failed to add rule file: %w", err)
		}
	}

	rules, err := compiler.GetRules()
	if err != nil {
		compiler.Destroy()
		return fmt.Errorf("failed to compile rules: %w", err)
	}

	if e.rules != nil {
		e.rules.Destroy()
	}

	e.compiler = compiler
	e.rules = rules
	e.initialized = true

	return nil
}

func (e *Engine) Name() string {
	return "YARA"
}

func (e *Engine) Scan(ctx context.Context, path string) (*scanner.ScanResult, error) {
	if !e.initialized {
		return nil, fmt.Errorf("engine not initialized")
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	result := &scanner.ScanResult{
		FilePath:   path,
		ScanEngine: "YARA",
		Infected:   false,
		Threats:    make([]scanner.Threat, 0),
	}

	matches, err := e.rules.ScanFile(path, 0, 0)
	if err != nil {
		return result, fmt.Errorf("scan error: %w", err)
	}

	if len(matches) > 0 {
		result.Infected = true
		for _, match := range matches {
			severity := "medium"
			if strings.Contains(strings.ToLower(match.Rule), "malware") ||
				strings.Contains(strings.ToLower(match.Rule), "trojan") ||
				strings.Contains(strings.ToLower(match.Rule), "ransomware") {
				severity = "high"
			} else if strings.Contains(strings.ToLower(match.Rule), "suspicious") {
				severity = "low"
			}

			description := fmt.Sprintf("YARA rule matched: %s", match.Rule)
			if match.Namespace != "" {
				description = fmt.Sprintf("YARA rule matched: %s (namespace: %s)", match.Rule, match.Namespace)
			}

			result.Threats = append(result.Threats, scanner.Threat{
				Name:        match.Rule,
				Severity:    severity,
				Description: description,
				Engine:      "YARA",
			})
		}
	}

	return result, nil
}

func (e *Engine) Update(ctx context.Context) error {
	if !e.initialized {
		return fmt.Errorf("engine not initialized")
	}

	return e.loadRules()
}

func (e *Engine) Close() error {
	if e.rules != nil {
		e.rules.Destroy()
		e.rules = nil
	}
	if e.compiler != nil {
		e.compiler.Destroy()
		e.compiler = nil
	}
	e.initialized = false
	return nil
}

func (e *Engine) GetRulesInfo() ([]string, error) {
	if !e.initialized || e.rules == nil {
		return nil, fmt.Errorf("engine not initialized")
	}

	var ruleNames []string
	rules := e.rules.GetRules()
	for _, rule := range rules {
		ruleNames = append(ruleNames, rule.Identifier())
	}

	return ruleNames, nil
}
