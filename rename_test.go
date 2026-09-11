package fsext

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicReplaceReplacesExistingDestination(t *testing.T) {
	directory := t.TempDir()
	oldPath, newPath := filepath.Join(directory, "next"), filepath.Join(directory, "active")
	if err := os.WriteFile(oldPath, []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := atomicReplace(oldPath, newPath); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(newPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "v2" {
		t.Fatalf("active=%q", body)
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatalf("source remains after replace: %v", err)
	}
}
