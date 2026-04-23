package ai

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// RuleGenInput captures the source material used to build a candidate rule.
type RuleGenInput struct {
	SourceType    string `json:"source_type"`
	SourceContent string `json:"source_content"`
	TargetService string `json:"target_service"`
	ProtocolHint  string `json:"protocol_hint"`
}

type RuleMatcher struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// RuleGenResult is the normalized model output before Suricata text assembly.
type RuleGenResult struct {
	Summary     string        `json:"summary"`
	Protocol    string        `json:"protocol"`
	Direction   string        `json:"direction"`
	AttackType  string        `json:"attack_type"`
	Message     string        `json:"message"`
	Classtype   string        `json:"classtype"`
	TargetPorts []string      `json:"target_ports"`
	Matchers    []RuleMatcher `json:"matchers"`
	RawResponse string        `json:"raw_response"`
}

// AlertAnalysisInput captures the context needed for AI alert explanation.
type AlertAnalysisInput struct {
	AlertID          string `json:"alert_id"`
	AgentID          string `json:"agent_id"`
	SID              string `json:"sid"`
	SignatureName    string `json:"signature_name"`
	Severity         string `json:"severity"`
	SourceIP         string `json:"source_ip"`
	DestIP           string `json:"dest_ip"`
	Payload          string `json:"payload"`
	AssetInfo        string `json:"asset_info"`
	AssetService     string `json:"asset_service"`
	AssetOS          string `json:"asset_os"`
	RiskScore        int    `json:"risk_score"`
	RuleAction       string `json:"rule_action"`
	RuleReason       string `json:"rule_reason"`
	AlertStatus      int    `json:"alert_status"`
	CreatedAt        string `json:"created_at"`
	RecentEventCount int    `json:"recent_event_count"`
	RecentAlertText  string `json:"recent_alert_text"`
	RecentOpsText    string `json:"recent_ops_text"`
	ExtractedSignals string `json:"extracted_signals"`
}

// AlertAnalysisResult is the persisted AI explanation payload.
type AlertAnalysisResult struct {
	Summary           string  `json:"summary"`
	AttackType        string  `json:"attack_type"`
	RiskReason        string  `json:"risk_reason"`
	ImpactScope       string  `json:"impact_scope"`
	EvidencePoints    string  `json:"evidence_points"`
	SuspiciousPath    string  `json:"suspicious_path"`
	SuspiciousParams  string  `json:"suspicious_params"`
	CommandFragments  string  `json:"command_fragments"`
	OperatorAdvice    string  `json:"operator_advice"`
	RecommendedAction string  `json:"recommended_action"`
	Confidence        float64 `json:"confidence"`
	RawResponse       string  `json:"raw_response"`
}

func (r *AlertAnalysisResult) UnmarshalJSON(data []byte) error {
	type alias AlertAnalysisResult
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	var result alias
	var err error

	if result.Summary, err = parseFlexibleJSONString(raw["summary"]); err != nil {
		return fmt.Errorf("summary: %w", err)
	}
	if result.AttackType, err = parseFlexibleJSONString(raw["attack_type"]); err != nil {
		return fmt.Errorf("attack_type: %w", err)
	}
	if result.RiskReason, err = parseFlexibleJSONString(raw["risk_reason"]); err != nil {
		return fmt.Errorf("risk_reason: %w", err)
	}
	if result.ImpactScope, err = parseFlexibleJSONString(raw["impact_scope"]); err != nil {
		return fmt.Errorf("impact_scope: %w", err)
	}
	if result.EvidencePoints, err = parseFlexibleJSONString(raw["evidence_points"]); err != nil {
		return fmt.Errorf("evidence_points: %w", err)
	}
	if result.SuspiciousPath, err = parseFlexibleJSONString(raw["suspicious_path"]); err != nil {
		return fmt.Errorf("suspicious_path: %w", err)
	}
	if result.SuspiciousParams, err = parseFlexibleJSONString(raw["suspicious_params"]); err != nil {
		return fmt.Errorf("suspicious_params: %w", err)
	}
	if result.CommandFragments, err = parseFlexibleJSONString(raw["command_fragments"]); err != nil {
		return fmt.Errorf("command_fragments: %w", err)
	}
	if result.OperatorAdvice, err = parseFlexibleJSONString(raw["operator_advice"]); err != nil {
		return fmt.Errorf("operator_advice: %w", err)
	}
	if result.RecommendedAction, err = parseFlexibleJSONString(raw["recommended_action"]); err != nil {
		return fmt.Errorf("recommended_action: %w", err)
	}
	if result.RawResponse, err = parseFlexibleJSONString(raw["raw_response"]); err != nil {
		return fmt.Errorf("raw_response: %w", err)
	}
	if result.Confidence, err = parseFlexibleJSONFloat(raw["confidence"]); err != nil {
		return fmt.Errorf("confidence: %w", err)
	}

	*r = AlertAnalysisResult(result)
	return nil
}

func parseFlexibleJSONString(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}

	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return strings.TrimSpace(asString), nil
	}

	var asStrings []string
	if err := json.Unmarshal(raw, &asStrings); err == nil {
		return strings.TrimSpace(strings.Join(asStrings, "\n")), nil
	}

	var asAny []interface{}
	if err := json.Unmarshal(raw, &asAny); err == nil {
		parts := make([]string, 0, len(asAny))
		for _, item := range asAny {
			text := strings.TrimSpace(fmt.Sprint(item))
			if text != "" && text != "<nil>" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, "\n"), nil
	}

	var asSingle interface{}
	if err := json.Unmarshal(raw, &asSingle); err == nil {
		text := strings.TrimSpace(fmt.Sprint(asSingle))
		if text == "<nil>" {
			return "", nil
		}
		return text, nil
	}

	return "", fmt.Errorf("unsupported json value: %s", string(raw))
}

func parseFlexibleJSONFloat(raw json.RawMessage) (float64, error) {
	if len(raw) == 0 {
		return 0, nil
	}

	var asFloat float64
	if err := json.Unmarshal(raw, &asFloat); err == nil {
		return asFloat, nil
	}

	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		asString = strings.TrimSpace(asString)
		if asString == "" {
			return 0, nil
		}
		value, err := strconv.ParseFloat(asString, 64)
		if err != nil {
			return 0, err
		}
		return value, nil
	}

	return 0, fmt.Errorf("unsupported json value: %s", string(raw))
}
