package executor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIPBlocker(t *testing.T) {
	blocker := NewIPBlocker()

	if blocker == nil {
		t.Fatal("Expected blocker, got nil")
	}

	// Test initial count
	if blocker.GetBlockCount() != 0 {
		t.Errorf("Expected initial count 0, got %d", blocker.GetBlockCount())
	}
}

func TestNginxPatcher(t *testing.T) {
	patcher := NewNginxPatcher()

	if patcher == nil {
		t.Fatal("Expected patcher, got nil")
	}

	// Test initial count
	if patcher.GetPatchCount() != 0 {
		t.Errorf("Expected initial count 0, got %d", patcher.GetPatchCount())
	}
}

func TestNginxPatcherGetConfigPath(t *testing.T) {
	patcher := NewNginxPatcher()

	// Test path generation - on Windows this will have backslashes
	result := patcher.GetConfigPath("default")

	// Verify it contains the expected components
	if len(result) == 0 {
		t.Error("Expected non-empty path")
	}

	// Check that it contains nginx and sites-available
	if !contains(result, "nginx") {
		t.Errorf("Expected path to contain 'nginx', got %s", result)
	}

	if !contains(result, "sites-available") {
		t.Errorf("Expected path to contain 'sites-available', got %s", result)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
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

func TestNginxPatcherInvalidRegex(t *testing.T) {
	patcher := NewNginxPatcher()

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

func TestIPBlockerGetBlockCount(t *testing.T) {
	blocker := NewIPBlocker()

	// Initially count should be 0
	if blocker.GetBlockCount() != 0 {
		t.Errorf("Expected initial count 0, got %d", blocker.GetBlockCount())
	}
}

func TestNginxPatcherGetPatchCount(t *testing.T) {
	patcher := NewNginxPatcher()

	// Initially count should be 0
	if patcher.GetPatchCount() != 0 {
		t.Errorf("Expected initial count 0, got %d", patcher.GetPatchCount())
	}
}
