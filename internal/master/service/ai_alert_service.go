package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"

	"security-response-system/internal/master/ai"
	"security-response-system/internal/master/model"
)

type AIAlertService struct {
	db       *gorm.DB
	provider ai.Provider
}

func NewAIAlertService(db *gorm.DB, provider ai.Provider) *AIAlertService {
	return &AIAlertService{
		db:       db,
		provider: provider,
	}
}

func (s *AIAlertService) Enabled() bool {
	return s != nil && s.provider != nil
}

func (s *AIAlertService) AnalyzeAlertByID(ctx context.Context, alertID string, force bool) (*model.AlertAIInsight, error) {
	if !s.Enabled() {
		return nil, fmt.Errorf("ai alert analysis is not enabled")
	}

	var cached model.AlertAIInsight
	if !force {
		if err := s.db.Where("alert_id = ?", alertID).First(&cached).Error; err == nil {
			return &cached, nil
		}
	} else {
		_ = s.db.Where("alert_id = ?", alertID).Delete(&model.AlertAIInsight{}).Error
	}

	var alert model.AlertLog
	if err := s.db.Where("alert_id = ?", alertID).First(&alert).Error; err != nil {
		return nil, err
	}

	var asset model.Asset
	_ = s.db.Where("ip = ?", alert.DestIP).First(&asset).Error

	var related []model.AlertLog
	_ = s.db.Where("source_ip = ? AND alert_id <> ?", alert.SourceIP, alert.AlertID).
		Order("created_at DESC").
		Limit(8).
		Find(&related).Error

	var recentOps []model.OperationLog
	_ = s.db.Where("alert_id = ?", alert.ID).
		Order("created_at DESC").
		Limit(5).
		Find(&recentOps).Error

	var recentEventCount int64
	_ = s.db.Model(&model.AlertLog{}).
		Where("source_ip = ? AND created_at >= ?", alert.SourceIP, time.Now().Add(-30*time.Minute)).
		Count(&recentEventCount).Error

	input := ai.AlertAnalysisInput{
		AlertID:          alert.AlertID,
		AgentID:          alert.AgentID,
		SID:              alert.SID,
		SignatureName:    alert.SignatureName,
		Severity:         alert.Severity,
		SourceIP:         alert.SourceIP,
		DestIP:           alert.DestIP,
		Payload:          decodePayloadForAI(alert.Payload),
		AssetInfo:        alert.AssetInfo,
		AssetService:     asset.ServiceType,
		AssetOS:          asset.OSType,
		RiskScore:        alert.RiskScore,
		RuleAction:       alert.Action,
		RuleReason:       buildRuleReason(alert, asset),
		AlertStatus:      alert.Status,
		CreatedAt:        alert.CreatedAt.Format(time.RFC3339),
		RecentEventCount: int(recentEventCount),
		RecentAlertText:  buildRecentAlertText(related),
		RecentOpsText:    buildRecentOpsText(recentOps),
		ExtractedSignals: buildExtractedSignals(decodePayloadForAI(alert.Payload)),
	}

	result, err := s.provider.AnalyzeAlert(ctx, input)
	if err != nil {
		return nil, err
	}
	result = normalizeAlertAnalysisResult(result, alert)

	insight := &model.AlertAIInsight{
		AlertID:           alert.AlertID,
		AlertLogID:        alert.ID,
		Summary:           result.Summary,
		AttackType:        result.AttackType,
		RiskReason:        result.RiskReason,
		ImpactScope:       result.ImpactScope,
		EvidencePoints:    result.EvidencePoints,
		SuspiciousPath:    result.SuspiciousPath,
		SuspiciousParams:  result.SuspiciousParams,
		CommandFragments:  result.CommandFragments,
		OperatorAdvice:    result.OperatorAdvice,
		RecommendedAction: result.RecommendedAction,
		Confidence:        result.Confidence,
		RawResponse:       result.RawResponse,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}
	if err := s.db.Create(insight).Error; err != nil {
		return nil, err
	}

	return insight, nil
}

func decodePayloadForAI(payload string) string {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return ""
	}

	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err == nil {
		text := strings.TrimSpace(string(decoded))
		if text != "" {
			return text
		}
	}

	return payload
}

func buildRuleReason(alert model.AlertLog, asset model.Asset) string {
	parts := []string{
		fmt.Sprintf("rule_action=%s", emptyText(alert.Action, "observe")),
		fmt.Sprintf("risk_score=%d", alert.RiskScore),
		fmt.Sprintf("severity=%s", emptyText(alert.Severity, "unknown")),
	}
	if strings.TrimSpace(asset.ServiceType) != "" {
		parts = append(parts, fmt.Sprintf("asset_service=%s", asset.ServiceType))
	}
	if strings.TrimSpace(asset.OSType) != "" {
		parts = append(parts, fmt.Sprintf("asset_os=%s", asset.OSType))
	}
	if strings.TrimSpace(alert.AssetInfo) != "" {
		parts = append(parts, fmt.Sprintf("asset_info=%s", trimText(alert.AssetInfo, 240)))
	}
	return strings.Join(parts, " | ")
}

func buildRecentAlertText(alerts []model.AlertLog) string {
	if len(alerts) == 0 {
		return ""
	}

	parts := make([]string, 0, len(alerts))
	for _, alert := range alerts {
		parts = append(parts, fmt.Sprintf(
			"%s|%s|%s|score=%d|action=%s",
			alert.CreatedAt.Format(time.RFC3339),
			alert.SignatureName,
			alert.Severity,
			alert.RiskScore,
			alert.Action,
		))
	}
	return strings.Join(parts, "\n")
}

func buildRecentOpsText(ops []model.OperationLog) string {
	if len(ops) == 0 {
		return ""
	}

	parts := make([]string, 0, len(ops))
	for _, op := range ops {
		parts = append(parts, fmt.Sprintf(
			"%s|type=%s|result=%d|target=%s|message=%s",
			op.CreatedAt.Format(time.RFC3339),
			op.CommandType,
			op.Result,
			trimText(op.Target, 120),
			trimText(op.Message, 160),
		))
	}
	return strings.Join(parts, "\n")
}

func normalizeAlertAnalysisResult(result *ai.AlertAnalysisResult, alert model.AlertLog) *ai.AlertAnalysisResult {
	if result == nil {
		return &ai.AlertAnalysisResult{
			Summary:           fallbackAlertSummary(alert),
			AttackType:        fallbackAttackType(alert),
			RiskReason:        fallbackRiskReason(alert),
			ImpactScope:       fallbackImpactScope(alert),
			EvidencePoints:    fallbackEvidencePoints(alert),
			SuspiciousPath:    fallbackSuspiciousPath(alert.Payload),
			SuspiciousParams:  fallbackSuspiciousParams(alert.Payload),
			CommandFragments:  fallbackCommandFragments(alert.Payload),
			OperatorAdvice:    fallbackOperatorAdvice(alert),
			RecommendedAction: normalizeRecommendedAction(alert.Action),
			Confidence:        0.35,
		}
	}

	result.Summary = emptyText(strings.TrimSpace(result.Summary), fallbackAlertSummary(alert))
	result.AttackType = emptyText(strings.TrimSpace(result.AttackType), fallbackAttackType(alert))
	result.RiskReason = emptyText(strings.TrimSpace(result.RiskReason), fallbackRiskReason(alert))
	result.ImpactScope = emptyText(strings.TrimSpace(result.ImpactScope), fallbackImpactScope(alert))
	result.EvidencePoints = emptyText(strings.TrimSpace(result.EvidencePoints), fallbackEvidencePoints(alert))
	result.SuspiciousPath = emptyText(strings.TrimSpace(result.SuspiciousPath), fallbackSuspiciousPath(alert.Payload))
	result.SuspiciousParams = emptyText(strings.TrimSpace(result.SuspiciousParams), fallbackSuspiciousParams(alert.Payload))
	result.CommandFragments = emptyText(strings.TrimSpace(result.CommandFragments), fallbackCommandFragments(alert.Payload))
	result.OperatorAdvice = emptyText(strings.TrimSpace(result.OperatorAdvice), fallbackOperatorAdvice(alert))
	result.RecommendedAction = normalizeRecommendedAction(result.RecommendedAction)
	result.Confidence = clampConfidence(result.Confidence)
	return result
}

func fallbackAlertSummary(alert model.AlertLog) string {
	return fmt.Sprintf("%s 告警来自 %s，目标 %s，当前规则动作为 %s。",
		emptyText(alert.SignatureName, "未知类型"),
		emptyText(alert.SourceIP, "未知来源"),
		emptyText(alert.DestIP, "未知目标"),
		emptyText(alert.Action, "observe"),
	)
}

func fallbackAttackType(alert model.AlertLog) string {
	name := strings.ToLower(alert.SignatureName)
	switch {
	case strings.Contains(name, "sql"):
		return "SQL 注入尝试"
	case strings.Contains(name, "xss"):
		return "XSS 尝试"
	case strings.Contains(name, "scan"), strings.Contains(name, "probe"):
		return "扫描探测"
	case strings.Contains(name, "brute"):
		return "爆破尝试"
	case strings.Contains(name, "rce"), strings.Contains(name, "command"):
		return "命令执行尝试"
	default:
		return "可疑网络攻击"
	}
}

func fallbackRiskReason(alert model.AlertLog) string {
	return fmt.Sprintf("规则引擎将该事件评分为 %d，严重等级为 %s，签名为 %s。",
		alert.RiskScore,
		emptyText(alert.Severity, "unknown"),
		emptyText(alert.SignatureName, "unknown"),
	)
}

func fallbackImpactScope(alert model.AlertLog) string {
	return fmt.Sprintf("该事件主要影响目标 %s，对应告警来源为 %s，建议结合目标主机业务服务判断实际暴露面。",
		emptyText(alert.DestIP, "未知目标"),
		emptyText(alert.SourceIP, "未知来源"),
	)
}

func fallbackEvidencePoints(alert model.AlertLog) string {
	return fmt.Sprintf("证据点包括：签名 %s、严重等级 %s、风险分 %d。",
		emptyText(alert.SignatureName, "unknown"),
		emptyText(alert.Severity, "unknown"),
		alert.RiskScore,
	)
}

func fallbackSuspiciousPath(payload string) string {
	signals := extractPayloadSignals(decodePayloadForAI(payload))
	return emptyText(signals.Path, "-")
}

func fallbackSuspiciousParams(payload string) string {
	signals := extractPayloadSignals(decodePayloadForAI(payload))
	if len(signals.Params) == 0 {
		return "-"
	}
	return strings.Join(signals.Params, ", ")
}

func fallbackCommandFragments(payload string) string {
	signals := extractPayloadSignals(decodePayloadForAI(payload))
	if len(signals.Commands) == 0 {
		return "-"
	}
	return strings.Join(signals.Commands, " | ")
}

func fallbackOperatorAdvice(alert model.AlertLog) string {
	switch normalizeRecommendedAction(alert.Action) {
	case "block":
		return "建议优先核实来源地址是否异常，如确认恶意可立即封禁并复核目标资产日志。"
	case "repair":
		return "建议尽快修复目标服务配置或漏洞点，并保留攻击样本用于复盘。"
	case "ignore":
		return "若已确认是白名单或误报来源，可记录依据后忽略该事件。"
	default:
		return "建议先观察同源后续行为，并结合原始载荷和资产上下文进行人工复核。"
	}
}

type payloadSignals struct {
	Path     string
	Params   []string
	Commands []string
}

func buildExtractedSignals(payload string) string {
	signals := extractPayloadSignals(payload)
	parts := []string{
		fmt.Sprintf("path=%s", emptyText(signals.Path, "-")),
		fmt.Sprintf("params=%s", emptyText(strings.Join(signals.Params, ","), "-")),
		fmt.Sprintf("commands=%s", emptyText(strings.Join(signals.Commands, " | "), "-")),
	}
	return strings.Join(parts, "\n")
}

func extractPayloadSignals(payload string) payloadSignals {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return payloadSignals{}
	}

	signals := payloadSignals{}
	lines := strings.Split(payload, "\n")
	if len(lines) > 0 {
		requestLine := strings.TrimSpace(lines[0])
		if fields := strings.Fields(requestLine); len(fields) >= 2 && strings.HasPrefix(fields[1], "/") {
			signals.Path = trimText(fields[1], 180)
		}
	}

	paramSet := map[string]struct{}{}
	paramPattern := regexp.MustCompile(`(?i)([a-z0-9_]{2,32})=`)
	for _, match := range paramPattern.FindAllStringSubmatch(payload, 20) {
		if len(match) > 1 {
			paramSet[strings.ToLower(match[1])] = struct{}{}
		}
	}
	for _, key := range []string{"cmd", "exec", "command", "query", "id", "url", "path", "file", "redirect", "dest"} {
		if strings.Contains(strings.ToLower(payload), key+"=") {
			paramSet[key] = struct{}{}
		}
	}
	signals.Params = sortedKeys(paramSet)

	commandSet := map[string]struct{}{}
	for _, token := range []string{"curl ", "wget ", "/bin/sh", "/bin/bash", "cmd.exe", "powershell", "chmod ", "nc ", "bash -c", "sh -c"} {
		if idx := strings.Index(strings.ToLower(payload), strings.ToLower(token)); idx >= 0 {
			commandSet[trimText(payload[idx:min(len(payload), idx+60)], 60)] = struct{}{}
		}
	}
	signals.Commands = sortedKeys(commandSet)
	return signals
}

func sortedKeys(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, 0, len(values))
	for value := range values {
		if strings.TrimSpace(value) != "" {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func normalizeRecommendedAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "ignore", "observe", "block", "repair":
		return strings.ToLower(strings.TrimSpace(action))
	case "patch":
		return "repair"
	case "unblock":
		return "observe"
	default:
		return "observe"
	}
}

func clampConfidence(confidence float64) float64 {
	switch {
	case confidence < 0:
		return 0
	case confidence > 1:
		return 1
	case confidence == 0:
		return 0.35
	default:
		return confidence
	}
}

func trimText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}

func emptyText(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
