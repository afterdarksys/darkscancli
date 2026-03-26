//go:build noclamav || windows
// +build noclamav windows

package clamav

import (
	"context"
	"fmt"

	"github.com/afterdarktech/darkscan/pkg/scanner"
)

type Engine struct {
	disabled bool
}

func New(dbPath string) (*Engine, error) {
	return nil, fmt.Errorf("ClamAV support is not available on this platform or was disabled at build time")
}

func (e *Engine) Name() string {
	return "ClamAV (disabled)"
}

func (e *Engine) Scan(ctx context.Context, path string) (*scanner.ScanResult, error) {
	return nil, fmt.Errorf("ClamAV support not available")
}

func (e *Engine) Update(ctx context.Context) error {
	return fmt.Errorf("ClamAV support not available")
}

func (e *Engine) Close() error {
	return nil
}

func GetVersion() string {
	return "disabled"
}

func GetDatabaseDirectory() (string, error) {
	return "", fmt.Errorf("ClamAV support not available")
}

func VerifyDatabase(dbPath string) error {
	return fmt.Errorf("ClamAV support not available")
}
