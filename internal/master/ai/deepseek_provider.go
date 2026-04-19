package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"security-response-system/internal/master/model"
)

type DeepSeekProvider struct {
	baseURL string
	apiKey  string
	model   string
	client  *http.Client
	prompts promptConfig
}

type promptConfig struct {
	ruleGenerationSystem string
	ruleGenerationUser   string
	alertAnalysisSystem  string
	alertAnalysisUser    string
}

type chatCompletionRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatCompletionResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func NewProviderFromConfig(cfg *model.Config) (Provider, error) {
	if cfg == nil || !cfg.Master.AI.Enabled {
		return nil, nil
	}

	switch strings.ToLower(strings.TrimSpace(cfg.Master.AI.Provider)) {
	case "", "api", "deepseek":
		return NewDeepSeekProvider(cfg)
	default:
		return nil, fmt.Errorf("unsupported ai provider: %s", cfg.Master.AI.Provider)
	}
}

func NewDeepSeekProvider(cfg *model.Config) (*DeepSeekProvider, error) {
	apiCfg := cfg.Master.AI.API
	if strings.TrimSpace(apiCfg.APIKey) == "" {
		return nil, fmt.Errorf("ai api_key is empty")
	}

	baseURL := strings.TrimRight(strings.TrimSpace(apiCfg.BaseURL), "/")
	if baseURL == "" {
		baseURL = "https://api.deepseek.com"
	}

	modelName := strings.TrimSpace(apiCfg.Model)
	if modelName == "" {
		modelName = "deepseek-chat"
	}

	timeout := time.Duration(apiCfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	return &DeepSeekProvider{
		baseURL: baseURL,
		apiKey:  apiCfg.APIKey,
		model:   modelName,
		client: &http.Client{
			Timeout: timeout,
		},
		prompts: promptConfig{
			ruleGenerationSystem: strings.TrimSpace(cfg.Master.AI.Prompts.RuleGenerationSystem),
			ruleGenerationUser:   strings.TrimSpace(cfg.Master.AI.Prompts.RuleGenerationUser),
			alertAnalysisSystem:  strings.TrimSpace(cfg.Master.AI.Prompts.AlertAnalysisSystem),
			alertAnalysisUser:    strings.TrimSpace(cfg.Master.AI.Prompts.AlertAnalysisUser),
		},
	}, nil
}

func (p *DeepSeekProvider) GenerateRule(ctx context.Context, input RuleGenInput) (*RuleGenResult, error) {
	systemPrompt := p.prompts.ruleGenerationSystem
	if systemPrompt == "" {
		systemPrompt = strings.Join([]string{
			"You are a security engineer that converts vulnerability intelligence into structured Suricata detection hints.",
			"Return JSON only with keys: summary, protocol, direction, attack_type, message, classtype, target_ports, matchers.",
			"direction must be one of: to_server, to_client, either.",
			"matchers must be an array of objects with keys type and value.",
			"Allowed matcher type values: content, pcre.",
			"Do not use custom matcher types such as method, uri, path, header, body, keyword, regex, or pattern.",
			"matchers must contain at least one usable matcher. If information is limited, still return one conservative content matcher.",
			"Prefer HTTP and web attack indicators when the input is a PoC for an HTTP vulnerability.",
			"Prefer stable request paths, parameter names, command fragments, header fragments, or exploit keywords that can be matched with content or pcre.",
			"Do not include markdown fences or commentary.",
		}, "\n")
	}

	userPrompt := p.prompts.ruleGenerationUser
	if userPrompt == "" {
		userPrompt = strings.Join([]string{
			"Please convert the following source material into structured Suricata rule hints.",
			"source_type: {{SOURCE_TYPE}}",
			"protocol_hint: {{PROTOCOL_HINT}}",
			"target_service: {{TARGET_SERVICE}}",
			"source_content:",
			"{{SOURCE_CONTENT}}",
			"",
			"Requirements:",
			"- Output JSON only.",
			"- matchers must contain at least one item.",
			"- Every matcher must use type=content or type=pcre.",
			"- Do not return matcher types like method, uri, path, header, body, regex, keyword, or pattern.",
			"- If there is only one stable feature, return one conservative content matcher instead of an empty array.",
		}, "\n")
	}
	userPrompt = strings.NewReplacer(
		"{{SOURCE_TYPE}}", emptyDefault(input.SourceType, "poc"),
		"{{PROTOCOL_HINT}}", emptyDefault(input.ProtocolHint, "http"),
		"{{TARGET_SERVICE}}", emptyDefault(input.TargetService, "web"),
		"{{SOURCE_CONTENT}}", input.SourceContent,
	).Replace(userPrompt)

	content, err := p.chat(ctx, systemPrompt, userPrompt)
	if err != nil {
		return nil, err
	}

	var result RuleGenResult
	if err := decodeJSONContent(content, &result); err != nil {
		return nil, fmt.Errorf("decode rule generation response: %w", err)
	}
	result.RawResponse = content
	return &result, nil
}

func (p *DeepSeekProvider) AnalyzeAlert(ctx context.Context, input AlertAnalysisInput) (*AlertAnalysisResult, error) {
	systemPrompt := p.prompts.alertAnalysisSystem
	if systemPrompt == "" {
		systemPrompt = strings.Join([]string{
			"You explain security alerts for operators in concise Chinese.",
			"Return JSON only with keys: summary, attack_type, risk_reason, impact_scope, evidence_points, suspicious_path, suspicious_params, command_fragments, operator_advice, recommended_action, confidence.",
			"recommended_action must be one of: ignore, observe, block, repair.",
			"confidence must be a number between 0 and 1.",
			"Prefer to explain the concrete attack intent, target impact, and why the current action is suitable.",
			"If available, extract concrete suspicious indicators such as path, parameter names, or command fragments.",
			"If the evidence is weak, be conservative and use observe instead of block.",
			"Do not include markdown fences or any extra text.",
		}, "\n")
	}

	userPrompt := p.prompts.alertAnalysisUser
	if userPrompt == "" {
		userPrompt = "alert_id: {{ALERT_ID}}\nagent_id: {{AGENT_ID}}\ncreated_at: {{CREATED_AT}}\nalert_status: {{ALERT_STATUS}}\nsid: {{SID}}\nsignature_name: {{SIGNATURE_NAME}}\nseverity: {{SEVERITY}}\nsource_ip: {{SOURCE_IP}}\ndest_ip: {{DEST_IP}}\npayload: {{PAYLOAD}}\nasset_info: {{ASSET_INFO}}\nasset_service: {{ASSET_SERVICE}}\nasset_os: {{ASSET_OS}}\nrisk_score: {{RISK_SCORE}}\nrule_action: {{RULE_ACTION}}\nrule_reason: {{RULE_REASON}}\nrecent_event_count: {{RECENT_EVENT_COUNT}}\nrecent_alerts:\n{{RECENT_ALERTS}}\nrecent_operations:\n{{RECENT_OPS}}\nextracted_signals:\n{{EXTRACTED_SIGNALS}}"
	}
	userPrompt = strings.NewReplacer(
		"{{ALERT_ID}}", input.AlertID,
		"{{AGENT_ID}}", input.AgentID,
		"{{CREATED_AT}}", input.CreatedAt,
		"{{ALERT_STATUS}}", fmt.Sprintf("%d", input.AlertStatus),
		"{{SID}}", input.SID,
		"{{SIGNATURE_NAME}}", input.SignatureName,
		"{{SEVERITY}}", input.Severity,
		"{{SOURCE_IP}}", input.SourceIP,
		"{{DEST_IP}}", input.DestIP,
		"{{PAYLOAD}}", trimForPrompt(input.Payload, 1200),
		"{{ASSET_INFO}}", input.AssetInfo,
		"{{ASSET_SERVICE}}", input.AssetService,
		"{{ASSET_OS}}", input.AssetOS,
		"{{RISK_SCORE}}", fmt.Sprintf("%d", input.RiskScore),
		"{{RULE_ACTION}}", input.RuleAction,
		"{{RULE_REASON}}", input.RuleReason,
		"{{RECENT_EVENT_COUNT}}", fmt.Sprintf("%d", input.RecentEventCount),
		"{{RECENT_ALERTS}}", trimForPrompt(input.RecentAlertText, 1800),
		"{{RECENT_OPS}}", trimForPrompt(input.RecentOpsText, 1200),
		"{{EXTRACTED_SIGNALS}}", trimForPrompt(input.ExtractedSignals, 800),
	).Replace(userPrompt)

	content, err := p.chat(ctx, systemPrompt, userPrompt)
	if err != nil {
		return nil, err
	}

	var result AlertAnalysisResult
	if err := decodeJSONContent(content, &result); err != nil {
		return nil, fmt.Errorf("decode alert analysis response: %w", err)
	}
	result = normalizeAlertResult(result)
	result.RawResponse = content
	return &result, nil
}

func (p *DeepSeekProvider) chat(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	reqBody := chatCompletionRequest{
		Model: p.model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		Temperature: 0.2,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/chat/completions", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var parsed chatCompletionResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", err
	}
	if resp.StatusCode >= 300 {
		if parsed.Error != nil && parsed.Error.Message != "" {
			return "", fmt.Errorf("deepseek api error: %s", parsed.Error.Message)
		}
		return "", fmt.Errorf("deepseek api returned status %d", resp.StatusCode)
	}
	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("deepseek api returned no choices")
	}

	return strings.TrimSpace(parsed.Choices[0].Message.Content), nil
}

func decodeJSONContent(content string, out interface{}) error {
	trimmed := strings.TrimSpace(content)
	trimmed = strings.TrimPrefix(trimmed, "```json")
	trimmed = strings.TrimPrefix(trimmed, "```")
	trimmed = strings.TrimSuffix(trimmed, "```")
	trimmed = strings.TrimSpace(trimmed)

	return json.Unmarshal([]byte(trimmed), out)
}

func emptyDefault(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func trimForPrompt(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "...(truncated)"
}

func normalizeAlertResult(result AlertAnalysisResult) AlertAnalysisResult {
	result.Summary = strings.TrimSpace(result.Summary)
	result.AttackType = strings.TrimSpace(result.AttackType)
	result.RiskReason = strings.TrimSpace(result.RiskReason)
	result.ImpactScope = strings.TrimSpace(result.ImpactScope)
	result.EvidencePoints = strings.TrimSpace(result.EvidencePoints)
	result.SuspiciousPath = strings.TrimSpace(result.SuspiciousPath)
	result.SuspiciousParams = strings.TrimSpace(result.SuspiciousParams)
	result.CommandFragments = strings.TrimSpace(result.CommandFragments)
	result.OperatorAdvice = strings.TrimSpace(result.OperatorAdvice)
	result.RecommendedAction = strings.ToLower(strings.TrimSpace(result.RecommendedAction))
	switch result.RecommendedAction {
	case "ignore", "observe", "block", "repair":
	default:
		result.RecommendedAction = ""
	}
	if result.Confidence < 0 {
		result.Confidence = 0
	}
	if result.Confidence > 1 {
		result.Confidence = 1
	}
	return result
}
