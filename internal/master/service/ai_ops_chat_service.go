package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"security-response-system/internal/master/ai"
	"security-response-system/internal/master/model"
)

type AIOpsChatService struct {
	db       *gorm.DB
	provider ai.ChatProvider
}

type AIOpsChatResponse struct {
	Answer         string   `json:"answer"`
	Days           int      `json:"days"`
	GeneratedAt    string   `json:"generated_at"`
	TotalAlerts    int64    `json:"total_alerts"`
	ContextSummary string   `json:"context_summary"`
	Suggestions    []string `json:"suggestions"`
}

type opsGroupCount struct {
	Label string `json:"label"`
	Count int64  `json:"count"`
}

func NewAIOpsChatService(db *gorm.DB, provider ai.Provider) *AIOpsChatService {
	chatProvider, _ := provider.(ai.ChatProvider)
	return &AIOpsChatService{
		db:       db,
		provider: chatProvider,
	}
}

func (s *AIOpsChatService) Enabled() bool {
	return s != nil && s.db != nil && s.provider != nil
}

func (s *AIOpsChatService) Ask(ctx context.Context, question string, days int) (*AIOpsChatResponse, error) {
	if !s.Enabled() {
		return nil, fmt.Errorf("ai operations chat is not enabled")
	}

	question = strings.TrimSpace(question)
	if question == "" {
		return nil, fmt.Errorf("question is required")
	}
	if days <= 0 {
		days = 7
	}
	if days > 30 {
		days = 30
	}

	now := time.Now()
	since := now.AddDate(0, 0, -days)
	contextText, total, err := s.buildSituationContext(since, now, days)
	if err != nil {
		return nil, err
	}

	systemPrompt := strings.Join([]string{
		"你是 DASRS 分布式自动化安全响应系统中的运维安全助手。",
		"你只能基于提供的 DASRS 近期告警统计、资产与操作上下文回答，不要编造未出现的 IP、主机、攻击类型或处置结果。",
		"回答面向值守运维人员，优先说明：攻击类型分布、被攻击最多的机器、主要攻击源、严重等级变化、建议的下一步核查动作。",
		"如果上下文不足，请明确说明缺少哪些数据。",
		"回答使用简洁中文，可以用短列表，但不要输出 Markdown 表格。",
	}, "\n")

	userPrompt := strings.Join([]string{
		"运维人员问题：",
		question,
		"",
		"DASRS 近期态势上下文：",
		contextText,
	}, "\n")

	answer, err := s.provider.Chat(ctx, systemPrompt, userPrompt)
	if err != nil {
		return nil, err
	}

	return &AIOpsChatResponse{
		Answer:         strings.TrimSpace(answer),
		Days:           days,
		GeneratedAt:    now.Format(time.RFC3339),
		TotalAlerts:    total,
		ContextSummary: firstLines(contextText, 10),
		Suggestions: []string{
			"最近 7 天什么攻击类型最多？",
			"哪台机器被攻击次数最高？",
			"有哪些来源 IP 需要优先封禁或复核？",
			"高危告警主要集中在哪些资产？",
		},
	}, nil
}

func (s *AIOpsChatService) buildSituationContext(since, now time.Time, days int) (string, int64, error) {
	base := s.db.Model(&model.AlertLog{}).Where("created_at >= ?", since)

	var total int64
	if err := base.Count(&total).Error; err != nil {
		return "", 0, err
	}

	attackTypes, err := s.groupAlertCounts(since, "COALESCE(NULLIF(attack_category, ''), NULLIF(signature_name, ''), '未分类')")
	if err != nil {
		return "", 0, err
	}
	targets, err := s.groupAlertCounts(since, "COALESCE(NULLIF(dest_ip, ''), '未知目标')")
	if err != nil {
		return "", 0, err
	}
	sources, err := s.groupAlertCounts(since, "COALESCE(NULLIF(source_ip, ''), '未知来源')")
	if err != nil {
		return "", 0, err
	}
	severities, err := s.groupAlertCounts(since, "COALESCE(NULLIF(severity, ''), 'unknown')")
	if err != nil {
		return "", 0, err
	}

	var recent []model.AlertLog
	if err := s.db.Where("created_at >= ?", since).
		Order("created_at DESC").
		Limit(12).
		Find(&recent).Error; err != nil {
		return "", 0, err
	}

	hostnames := s.lookupHostnames(targets)
	var builder strings.Builder
	fmt.Fprintf(&builder, "统计窗口：最近 %d 天，%s 至 %s\n", days, since.Format(time.RFC3339), now.Format(time.RFC3339))
	fmt.Fprintf(&builder, "告警总数：%d\n", total)
	writeGroup(&builder, "攻击类型 Top", attackTypes, nil)
	writeGroup(&builder, "被攻击目标 Top", targets, hostnames)
	writeGroup(&builder, "攻击来源 Top", sources, nil)
	writeGroup(&builder, "严重等级分布", severities, nil)
	builder.WriteString("最近告警样本：\n")
	if len(recent) == 0 {
		builder.WriteString("- 无近期告警样本\n")
	} else {
		for _, alert := range recent {
			category := strings.TrimSpace(alert.AttackCategory)
			if category == "" {
				category = strings.TrimSpace(alert.SignatureName)
			}
			if category == "" {
				category = "未分类"
			}
			fmt.Fprintf(
				&builder,
				"- %s | %s | %s -> %s | severity=%s | score=%d | action=%s | %s\n",
				alert.CreatedAt.Format(time.RFC3339),
				category,
				emptyText(alert.SourceIP, "unknown"),
				emptyText(alert.DestIP, "unknown"),
				emptyText(alert.Severity, "unknown"),
				alert.RiskScore,
				emptyText(alert.Action, "observe"),
				trimText(alert.SignatureName, 120),
			)
		}
	}

	return builder.String(), total, nil
}

func (s *AIOpsChatService) groupAlertCounts(since time.Time, expression string) ([]opsGroupCount, error) {
	var rows []opsGroupCount
	err := s.db.Model(&model.AlertLog{}).
		Select(expression+" AS label, COUNT(*) AS count").
		Where("created_at >= ?", since).
		Group(expression).
		Order("count DESC").
		Limit(8).
		Scan(&rows).Error
	return rows, err
}

func (s *AIOpsChatService) lookupHostnames(targets []opsGroupCount) map[string]string {
	if len(targets) == 0 {
		return nil
	}
	ips := make([]string, 0, len(targets))
	for _, item := range targets {
		if strings.TrimSpace(item.Label) != "" && item.Label != "未知目标" {
			ips = append(ips, item.Label)
		}
	}
	if len(ips) == 0 {
		return nil
	}

	var agents []model.AgentNode
	_ = s.db.Where("ip IN ?", ips).Find(&agents).Error
	hostnames := make(map[string]string, len(agents))
	for _, agent := range agents {
		name := strings.TrimSpace(agent.Hostname)
		if name == "" {
			name = strings.TrimSpace(agent.Name)
		}
		if name != "" {
			hostnames[agent.IP] = name
		}
	}
	return hostnames
}

func writeGroup(builder *strings.Builder, title string, items []opsGroupCount, labels map[string]string) {
	builder.WriteString(title + "：\n")
	if len(items) == 0 {
		builder.WriteString("- 无数据\n")
		return
	}
	for _, item := range items {
		label := emptyText(item.Label, "unknown")
		if labels != nil && strings.TrimSpace(labels[label]) != "" {
			label = fmt.Sprintf("%s(%s)", label, labels[label])
		}
		fmt.Fprintf(builder, "- %s: %d\n", label, item.Count)
	}
}

func firstLines(value string, limit int) string {
	lines := strings.Split(strings.TrimSpace(value), "\n")
	if len(lines) <= limit {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[:limit], "\n")
}
