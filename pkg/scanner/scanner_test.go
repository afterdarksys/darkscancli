package scanner

import (
	"context"
	"testing"
)

type mockEngine struct {
	name string
}

func (m *mockEngine) Name() string {
	return m.name
}

func (m *mockEngine) Scan(ctx context.Context, path string) (*ScanResult, error) {
	return &ScanResult{
		FilePath:   path,
		ScanEngine: m.name,
		Infected:   false,
		Threats:    []Threat{},
	}, nil
}

func (m *mockEngine) Update(ctx context.Context) error {
	return nil
}

func (m *mockEngine) Close() error {
	return nil
}

func TestNew(t *testing.T) {
	s := New()
	if s == nil {
		t.Fatal("New() returned nil")
	}
	if len(s.engines) != 0 {
		t.Errorf("Expected 0 engines, got %d", len(s.engines))
	}
}

func TestRegisterEngine(t *testing.T) {
	s := New()
	engine := &mockEngine{name: "test"}

	s.RegisterEngine(engine)

	if len(s.engines) != 1 {
		t.Errorf("Expected 1 engine, got %d", len(s.engines))
	}
}

func TestScanFile(t *testing.T) {
	s := New()
	s.RegisterEngine(&mockEngine{name: "mock1"})
	s.RegisterEngine(&mockEngine{name: "mock2"})

	ctx := context.Background()

	t.Run("no engines registered", func(t *testing.T) {
		s := New()
		_, err := s.ScanFile(ctx, "test.txt")
		if err == nil {
			t.Error("Expected error when no engines registered")
		}
	})
}
