package ai

import (
	"encoding/json"
	"testing"
)

func TestAlertAnalysisResultUnmarshalSupportsArrays(t *testing.T) {
	payload := []byte(`{
		"summary": "SQL 注入尝试",
		"attack_type": "sql_injection",
		"risk_reason": ["存在明显注入语句", "目标接口暴露"],
		"impact_scope": "可能读取敏感数据",
		"evidence_points": ["union select", "sleep(5)"],
		"suspicious_path": ["/admin/login", "/api/user"],
		"suspicious_params": ["id", "q"],
		"command_fragments": ["curl http://x", "bash -i"],
		"operator_advice": ["核查来源IP", "查看目标日志"],
		"recommended_action": "block",
		"confidence": "0.82"
	}`)

	var result AlertAnalysisResult
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if result.EvidencePoints != "union select\nsleep(5)" {
		t.Fatalf("unexpected evidence points: %q", result.EvidencePoints)
	}
	if result.SuspiciousParams != "id\nq" {
		t.Fatalf("unexpected suspicious params: %q", result.SuspiciousParams)
	}
	if result.OperatorAdvice != "核查来源IP\n查看目标日志" {
		t.Fatalf("unexpected operator advice: %q", result.OperatorAdvice)
	}
	if result.Confidence != 0.82 {
		t.Fatalf("unexpected confidence: %v", result.Confidence)
	}
}
