//go:build !cgo

package sandbox

import (
	"context"
	"errors"
	"io"

	"github.com/afterdarksys/darkscan/pkg/scanner"
)

type UnicornSandbox struct{}

func New() *UnicornSandbox { return &UnicornSandbox{} }

func (s *UnicornSandbox) Name() string { return "UnicornSandbox" }

func (s *UnicornSandbox) Update(_ context.Context) error { return nil }

func (s *UnicornSandbox) Close() error { return nil }

func (s *UnicornSandbox) Scan(_ context.Context, _ string) (*scanner.ScanResult, error) {
	return nil, errors.New("Unicorn sandbox requires CGO (not available in this build)")
}

func (s *UnicornSandbox) ScanReader(_ context.Context, _ io.Reader, _ string) (*scanner.ScanResult, error) {
	return nil, errors.New("Unicorn sandbox requires CGO (not available in this build)")
}
