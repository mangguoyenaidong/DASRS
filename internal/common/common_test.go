package common

import (
	"testing"
)

func TestGenerateUUID(t *testing.T) {
	uuid1 := GenerateUUID()
	uuid2 := GenerateUUID()

	// UUID should be 32 characters (hex encoded 16 bytes)
	if len(uuid1) != 32 {
		t.Errorf("Expected UUID length 32, got %d", len(uuid1))
	}

	// Each UUID should be unique
	if uuid1 == uuid2 {
		t.Error("Expected unique UUIDs, but they are the same")
	}

	// UUID should only contain hex characters
	for _, c := range uuid1 {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("UUID contains invalid character: %c", c)
		}
	}
}

func TestGetCurrentTimestamp(t *testing.T) {
	before := GetCurrentTimestamp()
	ts := GetCurrentTime().UnixMilli()
	after := GetCurrentTimestamp()

	if ts < before || ts > after {
		t.Error("Timestamp is not within expected range")
	}
}

func TestLoggerInfo(t *testing.T) {
	logger := NewLogger("[TEST]")

	// This should not panic
	logger.Info("Test message: %s", "info")
	logger.Error("Test message: %s", "error")
	logger.Debug("Test message: %s", "debug")
	logger.Warn("Test message: %s", "warn")
}

func TestLoggerGinLogger(t *testing.T) {
	logger := NewLogger("[TEST]")
	middleware := logger.GinLogger()

	if middleware == nil {
		t.Error("Expected middleware function, got nil")
	}
}
