package quarantine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRejectsTraversalIDs(t *testing.T) {
	manager, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"../outside", "valid/../../outside", "/tmp/outside", ""} {
		if err := manager.Delete(id); err == nil {
			t.Fatalf("Delete(%q) accepted an invalid ID", id)
		}
		if _, err := manager.GetEntry(id); err == nil {
			t.Fatalf("GetEntry(%q) accepted an invalid ID", id)
		}
	}
}

func TestValidEntryCanBeDeleted(t *testing.T) {
	root := t.TempDir()
	manager, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	id := "20260725_120000_abcdef12"
	if err := os.Mkdir(filepath.Join(root, id), 0700); err != nil {
		t.Fatal(err)
	}
	if err := manager.Delete(id); err != nil {
		t.Fatal(err)
	}
}
