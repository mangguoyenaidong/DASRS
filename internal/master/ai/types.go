package ai

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
