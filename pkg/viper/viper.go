package viper

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/afterdarktech/darkscan/pkg/scanner"
)

type Engine struct {
	viperPath   string
	projectName string
	initialized bool
}

type ViperNote struct {
	ID    int    `json:"id"`
	Title string `json:"title"`
	Body  string `json:"body"`
	Tags  string `json:"tags"`
}

func New(viperPath string) (*Engine, error) {
	if viperPath == "" {
		viperPath = "viper-cli"
	}

	if _, err := exec.LookPath(viperPath); err != nil {
		return nil, fmt.Errorf("viper executable not found at %s: %w", viperPath, err)
	}

	e := &Engine{
		viperPath:   viperPath,
		initialized: true,
	}

	return e, nil
}

func (e *Engine) Name() string {
	return "Viper"
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
		ScanEngine: "Viper",
		Infected:   false,
		Threats:    make([]scanner.Threat, 0),
	}

	hash, err := e.getFileHash(ctx, path)
	if err != nil {
		return result, fmt.Errorf("failed to get file hash: %w", err)
	}

	notes, err := e.searchByHash(ctx, hash)
	if err != nil {
		return result, fmt.Errorf("failed to search Viper database: %w", err)
	}

	if len(notes) > 0 {
		result.Infected = true
		for _, note := range notes {
			result.Threats = append(result.Threats, scanner.Threat{
				Name:        note.Title,
				Severity:    "medium",
				Description: fmt.Sprintf("Found in Viper database: %s (Tags: %s)", note.Body, note.Tags),
				Engine:      "Viper",
			})
		}
	}

	return result, nil
}

func (e *Engine) getFileHash(ctx context.Context, path string) (string, error) {
	cmd := exec.CommandContext(ctx, "sha256sum", path)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to calculate hash: %w", err)
	}

	parts := strings.Fields(string(output))
	if len(parts) == 0 {
		return "", fmt.Errorf("invalid hash output")
	}

	return parts[0], nil
}

func (e *Engine) searchByHash(ctx context.Context, hash string) ([]ViperNote, error) {
	args := []string{"-p", e.projectName, "find", "sha256", hash}
	cmd := exec.CommandContext(ctx, e.viperPath, args...)

	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 {
				return nil, nil
			}
		}
		return nil, fmt.Errorf("viper search failed: %w", err)
	}

	var notes []ViperNote
	if err := json.Unmarshal(output, &notes); err != nil {
		return nil, nil
	}

	return notes, nil
}

func (e *Engine) Update(ctx context.Context) error {
	return fmt.Errorf("viper database updates must be managed manually through viper-cli")
}

func (e *Engine) Close() error {
	e.initialized = false
	return nil
}

func (e *Engine) SetProject(projectName string) {
	e.projectName = projectName
}

func (e *Engine) GetProject() string {
	return e.projectName
}

func VerifyInstallation(viperPath string) error {
	if viperPath == "" {
		viperPath = "viper-cli"
	}

	cmd := exec.Command(viperPath, "--version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("viper is not properly installed or not in PATH: %w", err)
	}

	return nil
}

func (e *Engine) ListProjects(ctx context.Context) ([]string, error) {
	cmd := exec.CommandContext(ctx, e.viperPath, "projects", "-l")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list projects: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	var projects []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			projects = append(projects, line)
		}
	}

	return projects, nil
}

func (e *Engine) AddSample(ctx context.Context, path string, tags []string) error {
	args := []string{"-p", e.projectName, "add", path}
	if len(tags) > 0 {
		args = append(args, "-t", strings.Join(tags, ","))
	}

	cmd := exec.CommandContext(ctx, e.viperPath, args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add sample to Viper: %w", err)
	}

	return nil
}
