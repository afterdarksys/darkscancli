package scanner

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

type ScanResult struct {
	FilePath    string
	Infected    bool
	Threats     []Threat
	ScanEngine  string
	Error       error
}

type Threat struct {
	Name        string
	Severity    string
	Description string
	Engine      string
}

type Engine interface {
	Name() string
	Scan(ctx context.Context, path string) (*ScanResult, error)
	Update(ctx context.Context) error
	Close() error
}

type Scanner struct {
	engines []Engine
	mu      sync.RWMutex
}

func New() *Scanner {
	return &Scanner{
		engines: make([]Engine, 0),
	}
}

func (s *Scanner) RegisterEngine(engine Engine) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.engines = append(s.engines, engine)
}

func (s *Scanner) ScanFile(ctx context.Context, path string) ([]*ScanResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.engines) == 0 {
		return nil, fmt.Errorf("no scan engines registered")
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	if info.IsDir() {
		return nil, fmt.Errorf("path is a directory, use ScanDirectory instead")
	}

	results := make([]*ScanResult, 0, len(s.engines))
	for _, engine := range s.engines {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
			result, err := engine.Scan(ctx, path)
			if err != nil {
				results = append(results, &ScanResult{
					FilePath:   path,
					ScanEngine: engine.Name(),
					Error:      err,
				})
				continue
			}
			results = append(results, result)
		}
	}

	return results, nil
}

func (s *Scanner) ScanDirectory(ctx context.Context, path string, recursive bool) ([]*ScanResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.engines) == 0 {
		return nil, fmt.Errorf("no scan engines registered")
	}

	var results []*ScanResult
	var mu sync.Mutex

	err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			if !recursive && p != path {
				return filepath.SkipDir
			}
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			fileResults, err := s.scanFileInternal(ctx, p)
			if err != nil {
				return err
			}
			mu.Lock()
			results = append(results, fileResults...)
			mu.Unlock()
			return nil
		}
	})

	return results, err
}

func (s *Scanner) scanFileInternal(ctx context.Context, path string) ([]*ScanResult, error) {
	results := make([]*ScanResult, 0, len(s.engines))
	for _, engine := range s.engines {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
			result, err := engine.Scan(ctx, path)
			if err != nil {
				results = append(results, &ScanResult{
					FilePath:   path,
					ScanEngine: engine.Name(),
					Error:      err,
				})
				continue
			}
			results = append(results, result)
		}
	}
	return results, nil
}

func (s *Scanner) ScanReader(ctx context.Context, r io.Reader, name string) ([]*ScanResult, error) {
	tmpFile, err := os.CreateTemp("", "darkscan-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := io.Copy(tmpFile, r); err != nil {
		return nil, fmt.Errorf("failed to write to temp file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return nil, fmt.Errorf("failed to close temp file: %w", err)
	}

	return s.ScanFile(ctx, tmpFile.Name())
}

func (s *Scanner) UpdateEngines(ctx context.Context) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var errs []error
	for _, engine := range s.engines {
		if err := engine.Update(ctx); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", engine.Name(), err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors updating engines: %v", errs)
	}

	return nil
}

func (s *Scanner) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var errs []error
	for _, engine := range s.engines {
		if err := engine.Close(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", engine.Name(), err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing engines: %v", errs)
	}

	return nil
}
