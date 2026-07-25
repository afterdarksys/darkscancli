package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveUsesOwnerOnlyPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.json")
	if err := DefaultConfig().Save(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("config permissions = %04o, want 0600", got)
	}
}
