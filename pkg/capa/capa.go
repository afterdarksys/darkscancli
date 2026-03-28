package capa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/afterdarksys/darkscan/pkg/scanner"
)

type Engine struct {
	capaPath    string
	rulesPath   string
	initialized bool
}

type CapaOutput struct {
	Meta struct {
		File    string `json:"file"`
		Format  string `json:"format"`
		Arch    string `json:"arch"`
		OS      string `json:"os"`
		Version string `json:"version"`
	} `json:"meta"`
	Rules map[string]CapaRule `json:"rules"`
}

type CapaRule struct {
	Meta struct {
		Name      string   `json:"name"`
		Namespace string   `json:"namespace"`
		Scope     string   `json:"scope"`
		Attack    []Attack `json:"att&ck,omitempty"`
		MBC       []string `json:"mbc,omitempty"`
	} `json:"meta"`
	Matches []interface{} `json:"matches"`
}

type Attack struct {
	Tactic    string `json:"tactic"`
	Technique string `json:"technique"`
	ID        string `json:"id"`
}

func New(capaPath, rulesPath string) (*Engine, error) {
	if capaPath == "" {
		capaPath = "capa"
	}

	if _, err := exec.LookPath(capaPath); err != nil {
		return nil, fmt.Errorf("capa executable not found at %s: %w", capaPath, err)
	}

	e := &Engine{
		capaPath:    capaPath,
		rulesPath:   rulesPath,
		initialized: true,
	}

	return e, nil
}

func (e *Engine) Name() string {
	return "CAPA"
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
		ScanEngine: "CAPA",
		Infected:   false,
		Threats:    make([]scanner.Threat, 0),
	}

	args := []string{"-j", path}
	if e.rulesPath != "" {
		args = append([]string{"-r", e.rulesPath}, args...)
	}

	cmd := exec.CommandContext(ctx, e.capaPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 {
				return result, nil
			}
		}
		return result, fmt.Errorf("capa execution failed: %w (stderr: %s)", err, stderr.String())
	}

	var capaOutput CapaOutput
	if err := json.Unmarshal(stdout.Bytes(), &capaOutput); err != nil {
		return result, fmt.Errorf("failed to parse capa output: %w", err)
	}

	if len(capaOutput.Rules) > 0 {
		result.Infected = true

		for _, rule := range capaOutput.Rules {
			severity := e.determineSeverity(rule)
			description := e.buildDescription(rule)

			result.Threats = append(result.Threats, scanner.Threat{
				Name:        rule.Meta.Name,
				Severity:    severity,
				Description: description,
				Engine:      "CAPA",
			})
		}
	}

	return result, nil
}

func (e *Engine) determineSeverity(rule CapaRule) string {
	namespace := strings.ToLower(rule.Meta.Namespace)
	name := strings.ToLower(rule.Meta.Name)

	highRiskKeywords := []string{
		"ransomware", "keylog", "backdoor", "rootkit", "inject",
		"persistence", "credential", "privilege", "exploit",
	}

	for _, keyword := range highRiskKeywords {
		if strings.Contains(namespace, keyword) || strings.Contains(name, keyword) {
			return "high"
		}
	}

	if len(rule.Meta.Attack) > 0 {
		for _, attack := range rule.Meta.Attack {
			if strings.Contains(strings.ToLower(attack.Tactic), "execution") ||
				strings.Contains(strings.ToLower(attack.Tactic), "persistence") ||
				strings.Contains(strings.ToLower(attack.Tactic), "privilege") {
				return "high"
			}
		}
		return "medium"
	}

	return "medium"
}

func (e *Engine) buildDescription(rule CapaRule) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("Capability detected: %s", rule.Meta.Name))

	if rule.Meta.Namespace != "" {
		parts = append(parts, fmt.Sprintf("Namespace: %s", rule.Meta.Namespace))
	}

	if len(rule.Meta.Attack) > 0 {
		var attacks []string
		for _, attack := range rule.Meta.Attack {
			attacks = append(attacks, fmt.Sprintf("%s (%s)", attack.Technique, attack.ID))
		}
		parts = append(parts, fmt.Sprintf("ATT&CK: %s", strings.Join(attacks, ", ")))
	}

	if len(rule.Meta.MBC) > 0 {
		parts = append(parts, fmt.Sprintf("MBC: %s", strings.Join(rule.Meta.MBC, ", ")))
	}

	return strings.Join(parts, " | ")
}

func (e *Engine) Update(ctx context.Context) error {
	return fmt.Errorf("capa rule updates must be managed manually")
}

func (e *Engine) Close() error {
	e.initialized = false
	return nil
}

func GetVersion() (string, error) {
	cmd := exec.Command("capa", "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get capa version: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

func VerifyInstallation(capaPath string) error {
	if capaPath == "" {
		capaPath = "capa"
	}

	cmd := exec.Command(capaPath, "--version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("capa is not properly installed or not in PATH: %w", err)
	}

	return nil
}

func (e *Engine) ScanWithVerbose(ctx context.Context, path string) (*CapaOutput, error) {
	args := []string{"-j", path}
	if e.rulesPath != "" {
		args = append([]string{"-r", e.rulesPath}, args...)
	}

	cmd := exec.CommandContext(ctx, e.capaPath, args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("capa execution failed: %w", err)
	}

	var capaOutput CapaOutput
	if err := json.Unmarshal(output, &capaOutput); err != nil {
		return nil, fmt.Errorf("failed to parse capa output: %w", err)
	}

	return &capaOutput, nil
}
