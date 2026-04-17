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
	}, nil
}

func (p *DeepSeekProvider) GenerateRule(ctx context.Context, input RuleGenInput) (*RuleGenResult, error) {
	systemPrompt := strings.Join([]string{
		"You are a security engineer that converts vulnerability intelligence into structured Suricata detection hints.",
		"Return JSON only with keys: summary, protocol, direction, attack_type, message, classtype, target_ports, matchers.",
		"direction must be one of: to_server, to_client, either.",
		"matchers must be an array of objects with keys type and value.",
		"Allowed matcher type values: content, pcre.",
		"Prefer HTTP and web attack indicators when the input is a PoC for an HTTP vulnerability.",
		"Do not include markdown fences or commentary.",
	}, "\n")

	userPrompt := fmt.Sprintf(
		"source_type: %s\nprotocol_hint: %s\ntarget_service: %s\nsource_content:\n%s",
		emptyDefault(input.SourceType, "poc"),
		emptyDefault(input.ProtocolHint, "http"),
		emptyDefault(input.TargetService, "web"),
		input.SourceContent,
	)

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
	systemPrompt := strings.Join([]string{
		"You explain security alerts for operators in concise Chinese.",
		"Return JSON only with keys: summary, attack_type, risk_reason, recommended_action, confidence.",
		"recommended_action must be one of: ignore, observe, block, repair.",
		"confidence must be a number between 0 and 1.",
		"Do not include markdown fences or any extra text.",
	}, "\n")

	userPrompt := fmt.Sprintf(
		"alert_id: %s\nsid: %s\nsignature_name: %s\nseverity: %s\nsource_ip: %s\ndest_ip: %s\npayload: %s\nasset_info: %s\nasset_service: %s\nasset_os: %s\nrisk_score: %d\nrule_action: %s\nrule_reason: %s\nrecent_alerts: %s",
		input.AlertID,
		input.SID,
		input.SignatureName,
		input.Severity,
		input.SourceIP,
		input.DestIP,
		trimForPrompt(input.Payload, 1200),
		input.AssetInfo,
		input.AssetService,
		input.AssetOS,
		input.RiskScore,
		input.RuleAction,
		input.RuleReason,
		trimForPrompt(input.RecentAlertText, 1800),
	)

	content, err := p.chat(ctx, systemPrompt, userPrompt)
	if err != nil {
		return nil, err
	}

	var result AlertAnalysisResult
	if err := decodeJSONContent(content, &result); err != nil {
		return nil, fmt.Errorf("decode alert analysis response: %w", err)
	}
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
