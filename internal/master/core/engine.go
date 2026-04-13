package core

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"
	"security-response-system/internal/common"
	"security-response-system/internal/master/model"
)

// AlertGroup 告警组（关联的告警）
type AlertGroup struct {
	GroupID       string
	Alerts        []*AlertLogEntry
	AttackPattern string
	TotalScore    int
	StartTime     time.Time
	EndTime       time.Time
}

// AlertLogEntry 告警日志条目
type AlertLogEntry struct {
	AlertLog   *model.AlertLog
	Correlated bool
}

// IntelligenceEngine 情报分析引擎
type IntelligenceEngine struct {
	db     *gorm.DB
	redis  *redis.Client
	cfg    *model.Config
	logger *common.Logger
}

// NewIntelligenceEngine 创建引擎
func NewIntelligenceEngine(db *gorm.DB, redis *redis.Client, cfg *model.Config) *IntelligenceEngine {
	return &IntelligenceEngine{
		db:     db,
		redis:  redis,
		cfg:    cfg,
		logger: common.NewLogger("[Intelligence]"),
	}
}

// Analyze 分析告警并返回决策
func (e *IntelligenceEngine) Analyze(ctx context.Context, alert *Alert) (*Decision, error) {
	decision := &Decision{
		AlertID:   common.GenerateUUID(),
		Alert:     alert,
		Timestamp: time.Now().UnixMilli(),
	}

	// 1. 基础评分
	baseScore := e.calculateBaseScore(alert.Severity)
	decision.BaseScore = baseScore

	// 2. 上下文过滤 - 检查资产类型
	if alert.SignatureName != "" && alert.AssetInfo != "" {
		if e.isFalsePositive(alert, decision) {
			decision.Action = "ignore"
			decision.Score = 0
			decision.Reason = "False positive detected by context filtering"
			return decision, nil
		}
	}

	// 3. 时序分析 - 检查告警频率
	timeSeriesScore := e.analyzeTimeSeries(alert.SourceIP)
	decision.TimeSeriesScore = timeSeriesScore

	// 4. 计算最终评分
	finalScore := baseScore + timeSeriesScore
	decision.Score = finalScore

	// 5. 根据阈值决定动作
	if finalScore >= e.cfg.Master.Intelligence.RepairThreshold {
		decision.Action = "repair"
		decision.Reason = fmt.Sprintf("Score %d >= repair threshold %d", finalScore, e.cfg.Master.Intelligence.RepairThreshold)
	} else if finalScore >= e.cfg.Master.Intelligence.BlockThreshold {
		decision.Action = "block"
		decision.Reason = fmt.Sprintf("Score %d >= block threshold %d", finalScore, e.cfg.Master.Intelligence.BlockThreshold)
	} else {
		decision.Action = "ignore"
		decision.Reason = fmt.Sprintf("Score %d below block threshold %d", finalScore, e.cfg.Master.Intelligence.BlockThreshold)
	}

	e.logger.Info("Alert analyzed: %s -> Action: %s, Score: %d", alert.SID, decision.Action, finalScore)

	return decision, nil
}

// calculateBaseScore 计算基础评分
func (e *IntelligenceEngine) calculateBaseScore(severity string) int {
	switch severity {
	case "critical":
		return 100
	case "high":
		return 75
	case "medium":
		return 50
	case "low":
		return 25
	default:
		return 0
	}
}

// isFalsePositive 检查是否为误报
func (e *IntelligenceEngine) isFalsePositive(alert *Alert, decision *Decision) bool {
	// 示例：如果告警攻击类型是 "IIS" 但资产库显示该 IP 运行 "Nginx" -> 判定为误报
	// 这里需要从数据库查询资产信息
	var asset model.Asset
	result := e.db.Where("ip = ?", alert.SourceIP).First(&asset)
	if result.Error != nil {
		// 未找到资产，不做误报判定
		return false
	}

	// 检查攻击签名名称中是否包含与资产不匹配的服务
	if containsString(alert.SignatureName, []string{"IIS", "ASP.NET", "Windows"}) &&
		containsString(asset.ServiceType, []string{"Nginx", "Apache", "Linux"}) {
		return true
	}

	return false
}

// analyzeTimeSeries 时序分析
func (e *IntelligenceEngine) analyzeTimeSeries(sourceIP string) int {
	ctx := context.Background()
	key := fmt.Sprintf("alert:count:%s", sourceIP)

	// 增加计数
	count, err := e.redis.Incr(ctx, key).Result()
	if err != nil {
		e.logger.Error("Failed to increment Redis counter: %v", err)
		return 0
	}

	// 设置过期时间
	if count == 1 {
		e.redis.Expire(ctx, key, time.Duration(e.cfg.Master.Intelligence.TimeWindow)*time.Second)
	}

	// 根据频率计算加成
	if int(count) > e.cfg.Master.Intelligence.MaxAlertsPerWindow {
		return 50 // 高频加成
	} else if int(count) > e.cfg.Master.Intelligence.MaxAlertsPerWindow/2 {
		return 25 // 中频加成
	}

	return 0
}

// Decision 决策结果
type Decision struct {
	AlertID         string
	Alert           *Alert
	Score           int
	BaseScore       int
	TimeSeriesScore int
	Action          string
	Reason          string
	Timestamp       int64
}

// Alert 告警
type Alert struct {
	SID           string
	Payload       string
	SourceIP      string
	DestIP        string // 新增
	AssetInfo     string
	Timestamp     int64
	Severity      string
	SignatureName string
}

// isWhitelisted 检查 IP 是否在白名单中
func (e *IntelligenceEngine) isWhitelisted(ip string) bool {
	// 1. 检查静态配置白名单
	for _, wIP := range e.cfg.Master.Intelligence.Whitelist {
		if ip == wIP {
			return true
		}
	}

	// 2. 检查数据库动态白名单
	var count int64
	e.db.Model(&model.WhitelistIP{}).Where("ip = ?", ip).Count(&count)
	return count > 0
}

// IsIPBlocked 检查 IP 是否已被封禁
func (e *IntelligenceEngine) IsIPBlocked(ip string) bool {
	var count int64
	// 检查最近是否有针对该 IP 的封禁记录且未解封
	// 这里简化处理：检查最近 24 小时内是否有成功的 BLOCK_IP 操作
	// 实际生产中建议维护一个活跃封禁 IP 表
	e.db.Model(&model.OperationLog{}).
		Where("target = ? AND command_type = ? AND result = ? AND created_at >= ?", 
			ip, "block_ip", 1, time.Now().Add(-24*time.Hour)).
		Count(&count)
	
	return count > 0
}

// containsString 检查字符串是否包含列表中的任意元素
func containsString(s string, substrs []string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// GetAlertCorrelation 获取告警关联分析
func (e *IntelligenceEngine) GetAlertCorrelation(alertID string) (*AlertGroup, error) {
	var currentAlert model.AlertLog
	if err := e.db.Where("alert_id = ?", alertID).First(&currentAlert).Error; err != nil {
		return nil, fmt.Errorf("alert not found: %v", err)
	}

	// 查找关联的告警（相同源 IP 在时间窗口内的告警）
	timeWindow := time.Duration(e.cfg.Master.Intelligence.TimeWindow) * time.Second
	relatedAlerts := e.findRelatedAlerts(&currentAlert, timeWindow)

	// 构建告警组
	group := &AlertGroup{
		GroupID:       fmt.Sprintf("group-%s", alertID[:8]),
		AttackPattern: e.detectAttackPattern(&currentAlert, relatedAlerts),
		TotalScore:    currentAlert.RiskScore,
		StartTime:     currentAlert.CreatedAt,
		EndTime:       currentAlert.CreatedAt,
	}

	// 添加当前告警
	group.Alerts = append(group.Alerts, &AlertLogEntry{
		AlertLog:   &currentAlert,
		Correlated: false,
	})

	// 添加关联告警
	for i := range relatedAlerts {
		related := &relatedAlerts[i]
		group.TotalScore += related.RiskScore
		if related.CreatedAt.Before(group.StartTime) {
			group.StartTime = related.CreatedAt
		}
		if related.CreatedAt.After(group.EndTime) {
			group.EndTime = related.CreatedAt
		}
		group.Alerts = append(group.Alerts, &AlertLogEntry{
			AlertLog:   related,
			Correlated: true,
		})
	}

	e.logger.Info("Alert correlation analysis: GroupID=%s, TotalAlerts=%d, TotalScore=%d",
		group.GroupID, len(group.Alerts), group.TotalScore)

	return group, nil
}

// findRelatedAlerts 查找关联告警
func (e *IntelligenceEngine) findRelatedAlerts(currentAlert *model.AlertLog, timeWindow time.Duration) []model.AlertLog {
	var related []model.AlertLog

	// 查找条件：
	// 1. 相同源 IP
	// 2. 在时间窗口内
	// 3. 不同的告警 ID
	e.db.Where("source_ip = ? AND alert_id != ? AND created_at >= ?",
		currentAlert.SourceIP, currentAlert.AlertID, time.Now().Add(-timeWindow)).
		Order("created_at DESC").
		Limit(10).
		Find(&related)

	return related
}

// detectAttackPattern 检测攻击模式
func (e *IntelligenceEngine) detectAttackPattern(currentAlert *model.AlertLog, relatedAlerts []model.AlertLog) string {
	signature := currentAlert.SignatureName
	totalAlerts := len(relatedAlerts) + 1

	// 检测常见攻击模式
	patterns := []struct {
		Pattern string
		Name    string
	}{
		{"SQL", "SQL Injection Attack"},
		{"XSS", "Cross-Site Scripting"},
		{"Brute Force", "Brute Force Attack"},
		{"Port Scan", "Port Scanning"},
		{"DDoS", "DDoS Attack"},
		{"Malware", "Malware Activity"},
		{"Phishing", "Phishing Attempt"},
		{"Shellshock", "Shellshock Vulnerability Exploitation"},
		{"Heartbleed", "Heartbleed Exploitation"},
		{"Log4j", "Log4j Exploitation"},
	}

	for _, p := range patterns {
		if containsString(signature, []string{p.Pattern}) {
			if totalAlerts > 1 {
				return fmt.Sprintf("%s (Campaign with %d related alerts)", p.Name, totalAlerts-1)
			}
			return p.Name
		}
	}

	// 如果有多个关联告警但未识别模式
	if totalAlerts > 3 {
		return fmt.Sprintf("Coordinated Attack (%d alerts from %s)", totalAlerts, currentAlert.SourceIP)
	}

	return "Single Attack Attempt"
}

// GetAttackTrends 获取攻击趋势统计
func (e *IntelligenceEngine) GetAttackTrends(days int) (map[string]int, error) {
	stats := make(map[string]int)

	// 初始化最近几天的日期，确保即使某天没告警也会显示 0
	for i := 0; i < days; i++ {
		date := time.Now().AddDate(0, 0, -i).Format("2006-01-02")
		stats[date] = 0
	}

	var results []struct {
		Day   string `gorm:"column:day"`
		Count int    `gorm:"column:count"`
	}

	startDate := time.Now().AddDate(0, 0, -days)
	
	// 使用更通用的格式化查询 (MySQL 兼容)
	err := e.db.Model(&model.AlertLog{}).
		Select("DATE_FORMAT(created_at, '%Y-%m-%d') as day, COUNT(*) as count").
		Where("created_at >= ?", startDate).
		Group("day").
		Order("day ASC").
		Find(&results).Error

	if err != nil {
		e.logger.Error("Failed to query attack trends: %v", err)
		return stats, err
	}

	for _, r := range results {
		if r.Day != "" {
			stats[r.Day] = r.Count
		}
	}

	e.logger.Info("Attack trends query success: found %d active days in last %d days", len(results), days)
	return stats, nil
}

// GetTopAttackSources 获取Top攻击源
func (e *IntelligenceEngine) GetTopAttackSources(limit int) ([]map[string]interface{}, error) {
	var results []map[string]interface{}

	type SourceStat struct {
		SourceIP   string
		AlertCount int
		MaxScore   int
	}

	var stats []SourceStat
	e.db.Model(&model.AlertLog{}).
		Select("source_ip, COUNT(*) as alert_count, MAX(risk_score) as max_score").
		Group("source_ip").
		Order("alert_count DESC").
		Limit(limit).
		Find(&stats)

	for _, s := range stats {
		results = append(results, map[string]interface{}{
			"source_ip":   s.SourceIP,
			"alert_count": s.AlertCount,
			"max_risk":    s.MaxScore,
		})
	}

	return results, nil
}

// GetSeverityDistribution 获取严重程度分布
func (e *IntelligenceEngine) GetSeverityDistribution() (map[string]int, error) {
	type SeverityStat struct {
		Severity string
		Count    int
	}

	var stats []SeverityStat
	distribution := make(map[string]int)

	e.db.Model(&model.AlertLog{}).
		Select("severity, COUNT(*) as count").
		Group("severity").
		Find(&stats)

	for _, s := range stats {
		distribution[s.Severity] = s.Count
	}

	return distribution, nil
}

// GetActionStatistics 获取动作执行统计
func (e *IntelligenceEngine) GetActionStatistics() (map[string]int, error) {
	type ActionStat struct {
		Action string
		Count  int
	}

	var stats []ActionStat
	result := make(map[string]int)

	e.db.Model(&model.AlertLog{}).
		Select("action, COUNT(*) as count").
		Group("action").
		Find(&stats)

	for _, s := range stats {
		result[s.Action] = s.Count
	}

	return result, nil
}
