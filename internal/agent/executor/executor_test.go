package executor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIPBlocker_Initialization(t *testing.T) {
	blocker := NewIPBlocker()

	if blocker == nil {
		t.Fatal("Expected blocker, got nil")
	}

	// Test initial count
	if count := blocker.GetBlockCount(); count != 0 {
		t.Errorf("Expected initial count 0, got %d", count)
	}
}

func TestConfigPatcher_Initialization(t *testing.T) {
	patcher := NewConfigPatcher()

	if patcher == nil {
		t.Fatal("Expected patcher, got nil")
	}

	// Test initial count
	if count := patcher.GetPatchCount(); count != 0 {
		t.Errorf("Expected initial count 0, got %d", count)
	}
}

func TestCopyFile(t *testing.T) {
	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create source file
	srcPath := filepath.Join(tmpDir, "source.txt")
	dstPath := filepath.Join(tmpDir, "dest.txt")
	content := []byte("test content")

	if err := os.WriteFile(srcPath, content, 0644); err != nil {
		t.Fatal(err)
	}

	// Copy file
	if err := copyFile(srcPath, dstPath); err != nil {
		t.Fatalf("copyFile failed: %v", err)
	}

	// Verify content
	dstContent, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatal(err)
	}

	if string(dstContent) != string(content) {
		t.Errorf("Copied content = %s, want %s", string(dstContent), string(content))
	}
}

func TestConfigPatcher_InvalidRegex(t *testing.T) {
	patcher := NewConfigPatcher()

	// Create a temporary file for testing
	tmpDir, err := os.MkdirTemp("", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "nginx.conf")
	if err := os.WriteFile(configPath, []byte("server { listen 80; }"), 0644); err != nil {
		t.Fatal(err)
	}

	// Test with invalid regex - should return error
	err = patcher.SafePatch(configPath, "[invalid", "replacement")
	if err == nil {
		t.Error("Expected error for invalid regex, got nil")
	}
}
