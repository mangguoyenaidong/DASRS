package core

import (
	"testing"
	"time"

	"security-response-system/internal/master/model"
)

func TestCalculateBaseScore(t *testing.T) {
	engine := &IntelligenceEngine{}

	tests := []struct {
		severity string
		expected int
	}{
		{"critical", 80},
		{"high", 60},
		{"medium", 35},
		{"low", 15},
		{"unknown", 0},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			score := engine.calculateBaseScore(tt.severity)
			if score != tt.expected {
				t.Errorf("calculateBaseScore(%s) = %d, want %d", tt.severity, score, tt.expected)
			}
		})
	}
}

func TestContainsString(t *testing.T) {
	tests := []struct {
		s        string
		substrs  []string
		expected bool
	}{
		{"IIS attack detected", []string{"IIS", "ASP.NET"}, true},
		{"Nginx configuration", []string{"IIS", "Windows"}, false},
		{"Windows Server 2022", []string{"Windows", "Linux"}, true},
		{"", []string{"test"}, false},
		{"test", []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			result := containsString(tt.s, tt.substrs)
			if result != tt.expected {
				t.Errorf("containsString(%s, %v) = %v, want %v", tt.s, tt.substrs, result, tt.expected)
			}
		})
	}
}

func TestDecision(t *testing.T) {
	decision := &Decision{
		AlertID:         "test-alert-id",
		Score:           75,
		BaseScore:       50,
		TimeSeriesScore: 25,
		Action:          "block",
		Reason:          "Test decision",
		Timestamp:       time.Now().UnixMilli(),
	}

	if decision.AlertID != "test-alert-id" {
		t.Error("AlertID mismatch")
	}

	if decision.Action != "block" {
		t.Error("Action mismatch")
	}

	if decision.Score != 75 {
		t.Error("Score mismatch")
	}
}

func TestAlert(t *testing.T) {
	alert := &Alert{
		SID:           "2000001",
		Payload:       "test payload",
		SourceIP:      "192.168.1.100",
		AssetInfo:     "Linux Nginx",
		Timestamp:     time.Now().UnixMilli(),
		Severity:      "high",
		SignatureName: "SQL Injection",
	}

	if alert.SID != "2000001" {
		t.Error("SID mismatch")
	}

	if alert.SourceIP != "192.168.1.100" {
		t.Error("SourceIP mismatch")
	}

	if alert.Severity != "high" {
		t.Error("Severity mismatch")
	}
}

func TestAsset(t *testing.T) {
	asset := model.Asset{
		ID:          1,
		IP:          "192.168.1.100",
		Hostname:    "web-server-01",
		OSType:      "Linux",
		ServiceType: "Nginx",
		Status:      1,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if asset.IP != "192.168.1.100" {
		t.Error("IP mismatch")
	}

	if asset.ServiceType != "Nginx" {
		t.Error("ServiceType mismatch")
	}

	if asset.Status != 1 {
		t.Error("Status mismatch")
	}
}

func TestIntelligenceEngineStruct(t *testing.T) {
	engine := &IntelligenceEngine{}

	if engine == nil {
		t.Fatal("Expected engine, got nil")
	}

	// Verify default values
	if engine.db != nil {
		t.Error("Expected db to be nil")
	}

	if engine.redis != nil {
		t.Error("Expected redis to be nil")
	}
}

func TestSignatureKeywordsByService(t *testing.T) {
	engine := &IntelligenceEngine{}

	positive, negative := engine.signatureKeywordsByService("tomcat")
	if !containsString("apache tomcat jsp upload attempt", positive) {
		t.Fatal("expected tomcat positive keywords to match tomcat signature")
	}
	if !containsString("iis asp.net remote code execution", negative) {
		t.Fatal("expected tomcat negative keywords to match IIS signature")
	}
}

func TestGetEffectiveThresholds(t *testing.T) {
	cfg := &model.Config{}
	cfg.Master.Intelligence.BlockThreshold = 50
	cfg.Master.Intelligence.RepairThreshold = 80

	engine := &IntelligenceEngine{cfg: cfg}
	block, repair := engine.getEffectiveThresholds()
	if block != 50 || repair != 80 {
		t.Fatalf("expected default thresholds 50/80, got %d/%d", block, repair)
	}

	cfg.Master.Intelligence.DemoMode = true
	cfg.Master.Intelligence.DemoBlockThreshold = 40
	cfg.Master.Intelligence.DemoRepairThreshold = 65
	block, repair = engine.getEffectiveThresholds()
	if block != 40 || repair != 65 {
		t.Fatalf("expected demo thresholds 40/65, got %d/%d", block, repair)
	}
}

func TestCalculateDemoBonus(t *testing.T) {
	cfg := &model.Config{}
	cfg.Master.Intelligence.DemoMode = true
	cfg.Master.Intelligence.DemoExploitBonus = 15

	engine := &IntelligenceEngine{cfg: cfg}
	alert := &Alert{
		SignatureName: "Spring RCE attempt",
		Payload:       "POST /actuator/gateway/routes/test cmd=whoami",
	}

	bonus := engine.calculateDemoBonus(alert, 60, 25)
	if bonus <= 0 {
		t.Fatalf("expected positive demo bonus, got %d", bonus)
	}
}
