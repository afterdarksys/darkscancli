//go:build !cgo

package yara

import (
	"context"
	"fmt"
	"github.com/afterdarksys/darkscan/pkg/scanner"
)

type Engine struct {
	rulesPath string
}

func New(rulesPath string) (*Engine, error) {
	return nil, fmt.Errorf("YARA is not supported in this non-CGO build")
}

func (e *Engine) Name() string {
	return "YARA (disabled)"
}

func (e *Engine) Scan(ctx context.Context, path string) (*scanner.ScanResult, error) {
	return nil, fmt.Errorf("YARA is not supported")
}

func (e *Engine) Update(ctx context.Context) error {
	return fmt.Errorf("YARA is not supported")
}

func (e *Engine) Close() error {
	return nil
}
