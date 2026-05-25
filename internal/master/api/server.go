package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"security-response-system/internal/common"
	"security-response-system/internal/master/core"
	sgrpc "security-response-system/internal/master/grpc"
	"security-response-system/internal/master/model"
	"security-response-system/internal/proto"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Server HTTP API 服务器
type Server struct {
	router     *gin.Engine
	server     *http.Server
	cfg        *Config
	appCfg     *model.Config
	db         *gorm.DB
	redis      interface{}
	engine     *core.IntelligenceEngine
	logger     *common.Logger
	grpcServer *sgrpc.Server // 更新为自定义 gRPC server
}

// Config API 配置
type Config struct {
	Host string
	Port int
}

type agentServiceView struct {
	Name      string `json:"name"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	Process   string `json:"process"`
	Listen    string `json:"listen"`
	Status    string `json:"status"`
	Source    string `json:"source"`
	UpdatedAt string `json:"updated_at"`
}

type agentDetailView struct {
	model.AgentNode
	Services []agentServiceView `json:"services"`
}

// NewServer 创建服务器
func NewServer(cfg *model.Config, db *gorm.DB, redis interface{}, engine *core.IntelligenceEngine, grpcServer *sgrpc.Server) *Server {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	server := &Server{
		router: router,
		cfg: &Config{
			Host: cfg.Master.Host,
			Port: cfg.Master.HTTPPort,
		},
		appCfg:     cfg,
		db:         db,
		redis:      redis,
		engine:     engine,
		logger:     common.NewLogger("[HTTP-API]"),
		grpcServer: grpcServer,
	}

	server.setupRoutes()

	return server
}

// setupRoutes 设置路由
func (s *Server) setupRoutes() {
	// 中间件
	s.router.Use(gin.Recovery())
	s.router.Use(s.logger.GinLogger())

	// 加载模板
	s.router.LoadHTMLGlob("templates/*")

	// 管理页面
	s.router.GET("/", s.adminPage)
	s.router.GET("/admin", s.adminPage)

	// 健康检查
	s.router.GET("/health", s.healthCheck)

	// Agent 管理
	agents := s.router.Group("/api/agents")
	{
		agents.GET("", s.listAgents)
		agents.GET("/connected", s.listConnectedAgents)
		agents.GET("/:id", s.getAgent)
		agents.DELETE("/:id", s.deleteAgent)
		agents.POST("/:id/unblock", s.unblockAgentIP)
	}

	// 远程 Agent 注册 (供 Agent 启动时调用)
	s.router.POST("/api/agents/register", s.registerAgent)

	// 告警管理
	alerts := s.router.Group("/api/alerts")
	{
		alerts.GET("", s.listAlerts)
		alerts.GET("/:id", s.getAlert)
		alerts.GET("/:id/correlation", s.getAlertCorrelation)
		alerts.POST("/:id/repair", s.executeAlertRepair)
	}

	// 策略管理
	strategies := s.router.Group("/api/strategies")
	{
		strategies.GET("", s.listStrategies)
		strategies.GET("/:id", s.getStrategy)
		strategies.POST("", s.createStrategy)
		strategies.POST("/import", s.importStrategies)
		strategies.PUT("/:id", s.updateStrategy)
		strategies.DELETE("/:id", s.deleteStrategy)
	}

	// 资产统计
	s.router.GET("/api/stats", s.getStats)

	// 仪表盘统计
	dashboard := s.router.Group("/api/dashboard")
	{
		dashboard.GET("/overview", s.getDashboardOverview)
		dashboard.GET("/trends", s.getAttackTrends)
		dashboard.GET("/top-sources", s.getTopAttackSources)
		dashboard.GET("/severity-distribution", s.getSeverityDistribution)
		dashboard.GET("/action-stats", s.getActionStats)
	}

	// 手动封禁
	s.router.GET("/api/blocked-ips", s.listBlockedIPs)
	s.router.POST("/api/blocked-ips/sync", s.syncBlockedIPs)
	s.router.POST("/api/block", s.blockIP)
	s.router.POST("/api/unblock", s.unblockIP)
	s.router.POST("/api/batch-block", s.batchBlockIP)
	s.router.POST("/api/batch-unblock", s.batchUnblockIP)

	// 白名单管理
	whitelist := s.router.Group("/api/whitelist")
	{
		whitelist.GET("", s.listWhitelist)
		whitelist.POST("", s.addWhitelist)
		whitelist.DELETE("/:id", s.deleteWhitelist)
	}

	// 操作日志
	s.router.GET("/api/logs", s.getLogs)
}

// Start 启动服务器
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	s.server = &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Printf("HTTP API server listening on %s", addr)
	return s.server.ListenAndServe()
}

// Close 关闭服务器
func (s *Server) Close() {
	if s.server != nil {
		s.server.Close()
	}
}

// healthCheck 健康检查
func (s *Server) healthCheck(c *gin.Context) {
	s.db.Raw("SELECT 1").Scan(&struct{}{})
	c.PureJSON(http.StatusOK, gin.H{
		"status":    "ok",
		"timestamp": time.Now().UnixMilli(),
	})
}

// adminPage 管理页面
func (s *Server) adminPage(c *gin.Context) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.HTML(http.StatusOK, "index.html", gin.H{
		"title": "DASRS 管理控制台",
	})
}

// getLogs 获取操作日志
func (s *Server) getLogs(c *gin.Context) {
	var logs []model.OperationLog
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))

	offset := (page - 1) * pageSize

	var total int64
	s.db.Model(&model.OperationLog{}).Count(&total)

	if err := s.db.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&logs).Error; err != nil {
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.PureJSON(http.StatusOK, gin.H{
		"data":  logs,
		"total": total,
		"page":  page,
		"size":  pageSize,
	})
}

// listAgents 获取已注册的 Agent 节点列表
func (s *Server) listAgents(c *gin.Context) {
	var agents []model.AgentNode
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	offset := (page - 1) * pageSize
	query := s.db.Model(&model.AgentNode{})

	// 状态过滤
	if statusStr := c.Query("status"); statusStr != "" {
		status, _ := strconv.Atoi(statusStr)
		query = query.Where("status = ?", status)
	}

	// 搜索过滤
	if search := c.Query("search"); search != "" {
		query = query.Where("agent_id LIKE ? OR hostname LIKE ? OR name LIKE ?",
			"%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	var total int64
	query.Count(&total)

	if err := query.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&agents).Error; err != nil {
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.PureJSON(http.StatusOK, gin.H{
		"data":  agents,
		"total": total,
		"page":  page,
		"size":  pageSize,
	})
}

// listConnectedAgents returns nodes with an active command stream.
func (s *Server) listConnectedAgents(c *gin.Context) {
	if s.grpcServer == nil {
		c.PureJSON(http.StatusOK, gin.H{"success": true, "data": []interface{}{}})
		return
	}

	agents := s.grpcServer.GetConnectedAgents()
	data := make([]gin.H, 0, len(agents))
	for _, agent := range agents {
		if agent == nil {
			continue
		}
		data = append(data, gin.H{
			"agent_id":  agent.AgentID,
			"hostname":  agent.Hostname,
			"ip":        agent.IP,
			"last_seen": agent.LastSeen,
		})
	}
	c.PureJSON(http.StatusOK, gin.H{"success": true, "data": data})
}

// getAgent 获取单个 Agent 节点
func (s *Server) getAgent(c *gin.Context) {
	agentID := c.Param("id")
	if agentID == "" {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": "agent id required"})
		return
	}

	var agent model.AgentNode
	if err := s.db.Where("agent_id = ?", agentID).First(&agent).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.PureJSON(http.StatusNotFound, gin.H{"error": "Agent not found"})
			return
		}
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	detail := buildAgentDetail(agent)
	if len(detail.Services) == 0 && strings.TrimSpace(agent.IP) != "" {
		var asset model.Asset
		if err := s.db.Where("ip = ?", agent.IP).First(&asset).Error; err == nil && strings.TrimSpace(asset.ServiceType) != "" {
			detail.Services = []agentServiceView{{
				Name:      asset.ServiceType,
				Status:    "discovered",
				Source:    "asset-profile",
				UpdatedAt: asset.UpdatedAt.Format(time.RFC3339),
			}}
		}
	}

	c.PureJSON(http.StatusOK, gin.H{"data": detail})
}

// listAlerts 获取告警列表
func (s *Server) listAlerts(c *gin.Context) {
	var alertLogs []model.AlertLog
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	offset := (page - 1) * pageSize
	query := s.db.Model(&model.AlertLog{})

	// 严重程度过滤
	if severity := c.Query("severity"); severity != "" {
		query = query.Where("severity = ?", severity)
	}

	// 状态过滤
	if statusStr := c.Query("status"); statusStr != "" {
		status, _ := strconv.Atoi(statusStr)
		query = query.Where("status = ?", status)
	}

	// 动作过滤
	if action := c.Query("action"); action != "" {
		query = query.Where("action = ?", action)
	}

	// IP 过滤
	if sourceIP := c.Query("source_ip"); sourceIP != "" {
		query = query.Where("source_ip LIKE ?", "%"+sourceIP+"%")
	}
	if destIP := c.Query("dest_ip"); destIP != "" {
		query = query.Where("dest_ip LIKE ?", "%"+destIP+"%")
	}

	// 告警名称模糊过滤
	if sigName := c.Query("signature_name"); sigName != "" {
		query = query.Where("signature_name LIKE ?", "%"+sigName+"%")
	}

	// 白名单过滤
	if whitelistOnly := c.Query("whitelist_only"); whitelistOnly == "true" {
		query = query.Where("source_ip IN (SELECT ip FROM whitelist_ips)")
	}

	// 时间范围过滤
	if startTime := c.Query("start_time"); startTime != "" {
		t, _ := time.Parse("2006-01-02", startTime)
		query = query.Where("created_at >= ?", t)
	}
	if endTime := c.Query("end_time"); endTime != "" {
		t, _ := time.Parse("2006-01-02", endTime)
		query = query.Where("created_at <= ?", t.AddDate(0, 0, 1))
	}

	// 获取总数
	var total int64
	query.Count(&total)

	// 获取分页数据
	if err := query.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&alertLogs).Error; err != nil {
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 逻辑优化：如果 DestIP 看起来像网关或不准确，利用 AssetInfo 修正显示
	for i := range alertLogs {
		if (alertLogs[i].DestIP == "" || strings.HasSuffix(alertLogs[i].DestIP, ".254")) && alertLogs[i].AssetInfo != "" {
			// 在不破坏原始数据的前提下，为了前端显示友好，可以将资产名称附加在 IP 后
			// 或者在返回给前端的 JSON 中处理，这里直接简单替换 DestIP 用于显示
			if strings.Contains(alertLogs[i].AssetInfo, "Agent: ") {
				alertLogs[i].DestIP = strings.TrimPrefix(alertLogs[i].AssetInfo, "Agent: ")
			}
		}
	}

	c.PureJSON(http.StatusOK, gin.H{
		"data":  alertLogs,
		"total": total,
		"page":  page,
		"size":  pageSize,
	})
}

// getAlert 获取单个告警
func (s *Server) getAlert(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	var alertLog model.AlertLog
	if err := s.db.First(&alertLog, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.PureJSON(http.StatusNotFound, gin.H{"error": "alert not found"})
			return
		}
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.PureJSON(http.StatusOK, gin.H{"data": alertLog})
}

// listStrategies 获取策略列表
func (s *Server) listStrategies(c *gin.Context) {
	var strategies []model.Strategy
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	offset := (page - 1) * pageSize
	query := s.db.Model(&model.Strategy{})

	// 启用状态过滤
	if enabledStr := c.Query("enabled"); enabledStr != "" {
		enabled, _ := strconv.Atoi(enabledStr)
		query = query.Where("enabled = ?", enabled)
	}

	// 获取总数
	var total int64
	query.Count(&total)

	// 获取分页数据
	if err := query.Offset(offset).Limit(pageSize).Order("created_at DESC").Find(&strategies).Error; err != nil {
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.PureJSON(http.StatusOK, gin.H{
		"data":  strategies,
		"total": total,
		"page":  page,
		"size":  pageSize,
	})
}

// getStrategy 获取单个策略
func (s *Server) getStrategy(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	var strategy model.Strategy
	if err := s.db.First(&strategy, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.PureJSON(http.StatusNotFound, gin.H{"error": "strategy not found"})
			return
		}
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.PureJSON(http.StatusOK, gin.H{"data": strategy})
}

func normalizeStrategyInput(strategy *model.Strategy) {
	strategy.SID = strings.TrimSpace(strategy.SID)
	strategy.TargetFile = strings.TrimSpace(strategy.TargetFile)
	strategy.MatchRegex = strings.TrimSpace(strategy.MatchRegex)
	strategy.ReplaceContent = strings.TrimSpace(strategy.ReplaceContent)
	strategy.Description = strings.TrimSpace(strategy.Description)
	if strategy.Enabled != 0 {
		strategy.Enabled = 1
	}
}

func validateStrategyInput(strategy model.Strategy) error {
	if strings.TrimSpace(strategy.TargetFile) == "" {
		return errors.New("target_file is required")
	}
	if strings.TrimSpace(strategy.MatchRegex) == "" {
		return errors.New("match_regex is required")
	}
	if strings.TrimSpace(strategy.ReplaceContent) == "" {
		return errors.New("replace_content is required")
	}
	return nil
}

// createStrategy 创建策略
func (s *Server) createStrategy(c *gin.Context) {
	var strategy model.Strategy
	if err := c.ShouldBindJSON(&strategy); err != nil {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	normalizeStrategyInput(&strategy)
	if err := validateStrategyInput(strategy); err != nil {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := s.db.Create(&strategy).Error; err != nil {
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.PureJSON(http.StatusCreated, gin.H{
		"message": "strategy created",
		"data":    strategy,
	})
}

// updateStrategy 更新策略
func (s *Server) updateStrategy(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	var strategy model.Strategy
	if err := s.db.First(&strategy, id).Error; err != nil {
		c.PureJSON(http.StatusNotFound, gin.H{"error": "strategy not found"})
		return
	}

	if err := c.ShouldBindJSON(&strategy); err != nil {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	normalizeStrategyInput(&strategy)
	if err := validateStrategyInput(strategy); err != nil {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	s.db.Save(&strategy)
	c.PureJSON(http.StatusOK, gin.H{
		"message": "strategy updated",
		"data":    strategy,
	})
}

func (s *Server) importStrategies(c *gin.Context) {
	var req struct {
		Strategies []model.Strategy `json:"strategies"`
		Overwrite  bool             `json:"overwrite"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.Strategies) == 0 {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": "strategies is required"})
		return
	}

	created := 0
	updated := 0
	items := make([]model.Strategy, 0, len(req.Strategies))

	for idx, item := range req.Strategies {
		normalizeStrategyInput(&item)
		if err := validateStrategyInput(item); err != nil {
			c.PureJSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("strategy[%d]: %v", idx, err)})
			return
		}

		var existing model.Strategy
		err := s.db.Where("sid = ? AND target_file = ?", item.SID, item.TargetFile).First(&existing).Error
		switch {
		case err == nil:
			if req.Overwrite {
				existing.MatchRegex = item.MatchRegex
				existing.ReplaceContent = item.ReplaceContent
				existing.Description = item.Description
				existing.Enabled = item.Enabled
				if err := s.db.Save(&existing).Error; err != nil {
					c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
				items = append(items, existing)
				updated++
			} else {
				items = append(items, existing)
			}
		case errors.Is(err, gorm.ErrRecordNotFound):
			if err := s.db.Create(&item).Error; err != nil {
				c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			items = append(items, item)
			created++
		default:
			c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	c.PureJSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("strategy import completed: created %d, updated %d", created, updated),
		"data": gin.H{
			"created":    created,
			"updated":    updated,
			"total":      len(req.Strategies),
			"overwrite":  req.Overwrite,
			"strategies": items,
		},
	})
}

// deleteStrategy 删除策略
func (s *Server) deleteStrategy(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	if err := s.db.Delete(&model.Strategy{}, id).Error; err != nil {
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.PureJSON(http.StatusOK, gin.H{"message": "strategy deleted"})
}

// getStats 获取统计数据
func (s *Server) getStats(c *gin.Context) {
	var stats struct {
		TotalAssets       int64 `json:"total_assets"`
		OnlineAssets      int64 `json:"online_assets"`
		TotalAlerts       int64 `json:"total_alerts"`
		PendingAlerts     int64 `json:"pending_alerts"`
		BlockedIPs        int64 `json:"blocked_ips"`
		TotalStrategies   int64 `json:"total_strategies"`
		EnabledStrategies int64 `json:"enabled_strategies"`
	}

	s.db.Model(&model.AgentNode{}).Count(&stats.TotalAssets)
	s.db.Model(&model.AgentNode{}).Where("status = ?", 1).Count(&stats.OnlineAssets)
	s.db.Model(&model.AlertLog{}).Count(&stats.TotalAlerts)
	s.db.Model(&model.AlertLog{}).Where("status = ?", 0).Count(&stats.PendingAlerts)
	s.db.Model(&model.Strategy{}).Count(&stats.TotalStrategies)
	s.db.Model(&model.Strategy{}).Where("enabled = ?", 1).Count(&stats.EnabledStrategies)

	if blockedIPs, err := s.collectBlockedIPs(); err != nil {
		s.logger.Error("Failed to collect blocked ip stats: %v", err)
	} else {
		stats.BlockedIPs = int64(len(blockedIPs))
	}

	c.PureJSON(http.StatusOK, gin.H{"data": stats})
}

// listBlockedIPs 获取当前封禁中的 IP 列表 (基于操作日志)
func (s *Server) listBlockedIPs(c *gin.Context) {
	results, err := s.collectBlockedIPs()
	if err != nil {
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.PureJSON(http.StatusOK, gin.H{
		"success": true,
		"data":    results,
	})
}

// syncBlockedIPs asks online agents for their current iptables INPUT DROP rules.
func (s *Server) syncBlockedIPs(c *gin.Context) {
	var req struct {
		AgentID string `json:"agent_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	agents, err := s.resolveCommandAgents(req.AgentID)
	if err != nil {
		c.PureJSON(http.StatusConflict, gin.H{"success": false, "message": err.Error()})
		return
	}

	dispatched, err := s.queueBlockedIPSyncForAgents(agents)
	if err != nil {
		c.PureJSON(http.StatusConflict, gin.H{"success": false, "message": err.Error()})
		return
	}

	c.PureJSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("iptables block synchronization queued for %d online agent(s)", dispatched),
	})
}

type blockOperationSnapshot struct {
	ID              uint
	AgentID         string
	AgentIP         string
	CommandType     string
	Target          string
	Result          int
	Message         string
	ExecutionTimeMs int64
	CreatedAt       time.Time
}

func (blockOperationSnapshot) TableName() string {
	return "operation_logs"
}

func operationAgentKey(agentID, agentIP string) string {
	if ip := strings.TrimSpace(agentIP); ip != "" {
		return "ip:" + ip
	}
	if id := strings.TrimSpace(agentID); id != "" {
		return "id:" + id
	}
	return "__global__"
}

func (s *Server) buildAgentIPIndex() (map[string]string, error) {
	var agents []model.AgentNode
	if err := s.db.Select("agent_id", "ip").Find(&agents).Error; err != nil {
		return nil, err
	}

	index := make(map[string]string, len(agents))
	for _, agent := range agents {
		agentID := strings.TrimSpace(agent.AgentID)
		agentIP := strings.TrimSpace(agent.IP)
		if agentID == "" || agentIP == "" {
			continue
		}
		index[agentID] = agentIP
	}
	return index, nil
}

func resolveOperationAgentKey(item blockOperationSnapshot, agentIPIndex map[string]string) string {
	if key := operationAgentKey(item.AgentID, item.AgentIP); !strings.HasPrefix(key, "id:") {
		return key
	}
	agentID := strings.TrimSpace(item.AgentID)
	if agentID == "" {
		return ""
	}
	if agentIP := strings.TrimSpace(agentIPIndex[agentID]); agentIP != "" {
		return operationAgentKey(agentID, agentIP)
	}
	return ""
}

type blockedIPView struct {
	Target    string    `json:"ip"`
	CreatedAt time.Time `json:"blocked_at"`
	Message   string    `json:"reason"`
	Status    string    `json:"status"`
}

func (s *Server) collectBlockedIPs() ([]blockedIPView, error) {
	var logs []blockOperationSnapshot
	if err := s.db.Where("command_type IN ?", []string{"block_ip", "unblock_ip"}).
		Order("created_at DESC, id DESC").
		Find(&logs).Error; err != nil {
		return nil, err
	}
	agentIPIndex, err := s.buildAgentIPIndex()
	if err != nil {
		return nil, err
	}

	latestByAgentIP := make(map[string]blockOperationSnapshot)
	for _, item := range logs {
		ip := strings.TrimSpace(item.Target)
		if ip == "" {
			continue
		}
		agentKey := resolveOperationAgentKey(item, agentIPIndex)
		if agentKey == "" {
			continue
		}
		key := ip + "|" + agentKey
		if _, exists := latestByAgentIP[key]; exists {
			continue
		}
		latestByAgentIP[key] = item
	}

	aggregated := make(map[string]blockedIPView)
	for _, item := range latestByAgentIP {
		if item.CommandType != "block_ip" {
			continue
		}

		status := ""
		switch {
		case item.Result == 1:
			status = "active"
		case item.Result == 0 && item.ExecutionTimeMs == 0:
			status = "pending"
		default:
			continue
		}

		ip := strings.TrimSpace(item.Target)
		current, exists := aggregated[ip]
		if !exists || item.CreatedAt.After(current.CreatedAt) || (current.Status != "active" && status == "active") {
			aggregated[ip] = blockedIPView{
				Target:    ip,
				CreatedAt: item.CreatedAt,
				Message:   item.Message,
				Status:    status,
			}
		}
	}

	results := make([]blockedIPView, 0, len(aggregated))
	for _, item := range aggregated {
		results = append(results, item)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].CreatedAt.After(results[j].CreatedAt)
	})
	if len(results) > 100 {
		results = results[:100]
	}
	return results, nil
}

func (s *Server) getBlockState(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}

	var logs []blockOperationSnapshot
	err := s.db.Where("target = ? AND command_type IN ?", ip, []string{"block_ip", "unblock_ip"}).
		Order("created_at DESC, id DESC").
		Find(&logs).Error
	if err != nil || len(logs) == 0 {
		return ""
	}
	agentIPIndex, err := s.buildAgentIPIndex()
	if err != nil {
		return ""
	}

	latestByAgent := make(map[string]blockOperationSnapshot)
	for _, item := range logs {
		agentKey := resolveOperationAgentKey(item, agentIPIndex)
		if agentKey == "" {
			continue
		}
		if _, exists := latestByAgent[agentKey]; exists {
			continue
		}
		latestByAgent[agentKey] = item
	}

	hasActive := false
	hasPending := false
	hasUnblockPending := false
	for _, item := range latestByAgent {
		switch item.CommandType {
		case "block_ip":
			if item.Result == 1 {
				hasActive = true
			}
			if item.Result == 0 && item.ExecutionTimeMs == 0 {
				hasPending = true
			}
		case "unblock_ip":
			if item.Result == 0 && item.ExecutionTimeMs == 0 {
				hasUnblockPending = true
			}
		}
	}

	switch {
	case hasActive:
		return "active"
	case hasPending:
		return "pending"
	case hasUnblockPending:
		return "unblock_pending"
	}

	return ""
}

func (s *Server) resolveCommandAgents(targetAgentID string) ([]*sgrpc.AgentInfo, error) {
	if s.grpcServer == nil {
		return nil, errors.New("grpc server unavailable")
	}
	if agentID := strings.TrimSpace(targetAgentID); agentID != "" {
		for _, agent := range s.grpcServer.GetConnectedAgents() {
			if agent != nil && agent.AgentID == agentID {
				return []*sgrpc.AgentInfo{agent}, nil
			}
		}
		return nil, fmt.Errorf("target agent %s is not connected", agentID)
	}
	agents := s.grpcServer.GetConnectedAgents()
	if len(agents) == 0 {
		return nil, errors.New("no connected agents available")
	}
	return agents, nil
}

func (s *Server) resolveUnblockAgents(ip, targetAgentID string) ([]*sgrpc.AgentInfo, error) {
	if strings.TrimSpace(targetAgentID) != "" {
		return s.resolveCommandAgents(targetAgentID)
	}

	var logs []blockOperationSnapshot
	if err := s.db.Where("target = ? AND command_type IN ?", strings.TrimSpace(ip), []string{"block_ip", "unblock_ip"}).
		Order("created_at DESC, id DESC").
		Find(&logs).Error; err != nil {
		return nil, err
	}
	agentIPIndex, err := s.buildAgentIPIndex()
	if err != nil {
		return nil, err
	}

	latestByAgent := make(map[string]blockOperationSnapshot)
	for _, item := range logs {
		agentKey := resolveOperationAgentKey(item, agentIPIndex)
		if agentKey == "" {
			continue
		}
		if _, exists := latestByAgent[agentKey]; exists {
			continue
		}
		latestByAgent[agentKey] = item
	}
	if len(latestByAgent) == 0 {
		return s.resolveCommandAgents("")
	}

	connectedByKey := make(map[string]*sgrpc.AgentInfo)
	for _, agent := range s.grpcServer.GetConnectedAgents() {
		if agent != nil {
			connectedByKey[operationAgentKey(agent.AgentID, agent.IP)] = agent
		}
	}

	selected := make([]*sgrpc.AgentInfo, 0, len(latestByAgent))
	for agentKey, item := range latestByAgent {
		if item.CommandType != "block_ip" {
			continue
		}
		if item.Result != 1 && !(item.Result == 0 && item.ExecutionTimeMs == 0) {
			continue
		}
		if agent, ok := connectedByKey[agentKey]; ok {
			selected = append(selected, agent)
		}
	}
	if len(selected) > 0 {
		return selected, nil
	}
	return s.resolveCommandAgents("")
}

func (s *Server) queueCommandForAgents(commandType string, targetIP, reason string, agents []*sgrpc.AgentInfo, protoType proto.CommandType) (int, error) {
	targetIP = strings.TrimSpace(targetIP)
	if targetIP == "" {
		return 0, errors.New("target ip is required")
	}
	if len(agents) == 0 {
		return 0, errors.New("no eligible connected agents available")
	}
	if strings.TrimSpace(reason) == "" {
		reason = strings.ReplaceAll(commandType, "_", " ")
	}

	dispatched := 0
	now := time.Now()
	for idx, agent := range agents {
		if agent == nil {
			continue
		}
		commandID := fmt.Sprintf("%s-%d-%d", strings.ReplaceAll(commandType, "_", "-"), now.UnixNano(), idx)
		if err := s.db.Create(&model.OperationLog{
			CommandID:   commandID,
			AgentID:     agent.AgentID,
			AgentIP:     strings.TrimSpace(agent.IP),
			CommandType: commandType,
			Target:      targetIP,
			Result:      0,
			Message:     reason,
			CreatedAt:   time.Now(),
		}).Error; err != nil {
			s.logger.Error("Failed to create operation log for %s on agent %s: %v", commandType, agent.AgentID, err)
			continue
		}
		s.grpcServer.QueueCommand(agent.AgentID, &proto.CommandMessage{
			CommandId: commandID,
			Type:      protoType,
			TargetIp:  targetIP,
		})
		dispatched++
	}
	if dispatched == 0 {
		return 0, errors.New("no eligible connected agents available")
	}
	return dispatched, nil
}

func (s *Server) queueBlockedIPSyncForAgents(agents []*sgrpc.AgentInfo) (int, error) {
	if len(agents) == 0 {
		return 0, errors.New("no eligible connected agents available")
	}

	dispatched := 0
	now := time.Now()
	for idx, agent := range agents {
		if agent == nil {
			continue
		}
		commandID := fmt.Sprintf("sync-blocked-ips-%d-%d", now.UnixNano(), idx)
		if err := s.db.Create(&model.OperationLog{
			CommandID:   commandID,
			AgentID:     agent.AgentID,
			AgentIP:     strings.TrimSpace(agent.IP),
			CommandType: "sync_blocked_ips",
			Target:      "iptables INPUT DROP",
			Result:      0,
			Message:     "Queued iptables block synchronization",
			CreatedAt:   time.Now(),
		}).Error; err != nil {
			s.logger.Error("Failed to create iptables synchronization log for agent %s: %v", agent.AgentID, err)
			continue
		}

		s.grpcServer.QueueCommand(agent.AgentID, &proto.CommandMessage{
			CommandId:  commandID,
			Type:       proto.CommandType_PATCH_CONFIG,
			MatchRegex: "__DASRS_IPTABLES_BLOCK_SYNC__",
		})
		dispatched++
	}

	if dispatched == 0 {
		return 0, errors.New("no eligible connected agents available")
	}
	return dispatched, nil
}

func (s *Server) resolveRepairAgents(alert model.AlertLog) ([]*sgrpc.AgentInfo, error) {
	if s.grpcServer == nil {
		return nil, errors.New("grpc server unavailable")
	}

	destIP := strings.TrimSpace(alert.DestIP)
	if destIP != "" {
		selected := make([]*sgrpc.AgentInfo, 0, 1)
		for _, agent := range s.grpcServer.GetConnectedAgents() {
			if agent != nil && strings.TrimSpace(agent.IP) == destIP {
				selected = append(selected, agent)
			}
		}
		if len(selected) > 0 {
			return selected, nil
		}
	}

	if alertAgentID := strings.TrimSpace(alert.AgentID); alertAgentID != "" {
		return s.resolveCommandAgents(alertAgentID)
	}

	if destIP != "" {
		return nil, fmt.Errorf("no connected agent matches alert target asset %s", destIP)
	}
	return nil, errors.New("alert has no target asset information for repair")
}

func (s *Server) queueRepairCommandForAgents(alert model.AlertLog, strategy model.Strategy, agents []*sgrpc.AgentInfo) (int, error) {
	if len(agents) == 0 {
		return 0, errors.New("no eligible connected agents available")
	}

	configPath := strings.TrimSpace(strategy.TargetFile)
	if configPath == "" {
		return 0, errors.New("repair strategy target_file is empty")
	}
	matchRegex := strings.TrimSpace(strategy.MatchRegex)
	replaceContent := strategy.ReplaceContent
	if matchRegex == "" || strings.TrimSpace(replaceContent) == "" {
		return 0, errors.New("repair strategy content is incomplete")
	}

	reason := strings.TrimSpace(strategy.Description)
	if reason == "" {
		reason = "manual repair approved"
	}

	dispatched := 0
	now := time.Now()
	for idx, agent := range agents {
		if agent == nil {
			continue
		}
		commandID := fmt.Sprintf("repair-alert-%d-%d", now.UnixNano(), idx)
		if err := s.db.Create(&model.OperationLog{
			CommandID:   commandID,
			AgentID:     agent.AgentID,
			AgentIP:     strings.TrimSpace(agent.IP),
			AlertID:     alert.ID,
			CommandType: "patch_config",
			Target:      configPath,
			Result:      0,
			Message:     fmt.Sprintf("人工审核确认修复: %s", reason),
			CreatedAt:   time.Now(),
		}).Error; err != nil {
			s.logger.Error("Failed to create repair operation log for alert %d on agent %s: %v", alert.ID, agent.AgentID, err)
			continue
		}

		s.grpcServer.QueueCommand(agent.AgentID, &proto.CommandMessage{
			CommandId:      commandID,
			Type:           proto.CommandType_PATCH_CONFIG,
			ConfigPath:     configPath,
			MatchRegex:     matchRegex,
			ReplaceContent: replaceContent,
		})
		dispatched++
	}

	if dispatched == 0 {
		return 0, errors.New("no eligible connected agents available")
	}
	return dispatched, nil
}

func (s *Server) executeAlertRepair(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": "invalid alert id"})
		return
	}

	var alert model.AlertLog
	if err := s.db.First(&alert, uint(id)).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.PureJSON(http.StatusNotFound, gin.H{"error": "alert not found"})
			return
		}
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if strings.ToLower(strings.TrimSpace(alert.Action)) != "repair" {
		c.PureJSON(http.StatusConflict, gin.H{"error": "alert is not waiting for manual repair review"})
		return
	}
	if alert.Status == 1 {
		c.PureJSON(http.StatusConflict, gin.H{"error": "alert repair has already been reviewed"})
		return
	}

	var strategy model.Strategy
	if err := s.db.Where("sid = ? AND enabled = 1", strings.TrimSpace(alert.SID)).First(&strategy).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.PureJSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("no enabled repair strategy found for SID %s", alert.SID)})
			return
		}
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	agents, err := s.resolveRepairAgents(alert)
	if err != nil {
		c.PureJSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	dispatched, err := s.queueRepairCommandForAgents(alert, strategy, agents)
	if err != nil {
		c.PureJSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	if err := s.db.Model(&alert).Updates(map[string]interface{}{
		"status":     1,
		"updated_at": time.Now(),
	}).Error; err != nil {
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	s.logger.Info("Manual repair approved for alert %d (SID: %s), dispatched to %d agent(s)", alert.ID, alert.SID, dispatched)
	c.PureJSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("Repair command queued for alert %d to %d agent(s)", alert.ID, dispatched),
		"data": gin.H{
			"alert_id":     alert.ID,
			"strategy_id":  strategy.ID,
			"target_file":  strategy.TargetFile,
			"agent_count":  dispatched,
			"target_asset": alert.DestIP,
		},
	})
}

func (s *Server) syncAlertActionForIP(ip, action string) {
	ip = strings.TrimSpace(ip)
	action = strings.TrimSpace(action)
	if ip == "" || action == "" {
		return
	}

	query := s.db.Model(&model.AlertLog{}).Where("source_ip = ?", ip)
	switch action {
	case "block":
		query = query.Where("status = ?", 0)
	case "unblock":
		query = query.Where("action = ?", "block")
	}

	if err := query.Updates(map[string]interface{}{
		"action": action,
		"status": 1,
	}).Error; err != nil {
		s.logger.Error("Failed to sync alert action for ip %s to %s: %v", ip, action, err)
	}
}

// blockIP 手动封禁 IP
func (s *Server) blockIP(c *gin.Context) {
	var req struct {
		IP      string `json:"ip" binding:"required"`
		Reason  string `json:"reason"`
		AgentID string `json:"agent_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 强制白名单检查
	if s.engine.IsWhitelisted(req.IP) {
		c.PureJSON(http.StatusForbidden, gin.H{
			"success": false,
			"message": fmt.Sprintf("IP %s 在白名单中，拒绝封禁操作", req.IP),
		})
		return
	}

	switch s.getBlockState(req.IP) {
	case "active":
		c.PureJSON(http.StatusConflict, gin.H{
			"success": false,
			"message": fmt.Sprintf("IP %s is already blocked", req.IP),
		})
		return
	case "pending":
		c.PureJSON(http.StatusConflict, gin.H{
			"success": false,
			"message": fmt.Sprintf("IP %s already has a pending block command", req.IP),
		})
		return
	}

	agents, err := s.resolveCommandAgents(req.AgentID)
	if err != nil {
		c.PureJSON(http.StatusConflict, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	dispatched, err := s.queueCommandForAgents("block_ip", req.IP, req.Reason, agents, proto.CommandType_BLOCK_IP)
	if err != nil {
		c.PureJSON(http.StatusConflict, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	s.logger.Info("Manual block command sent for IP: %s, reason: %s, agent: %s", req.IP, req.Reason, req.AgentID)
	s.syncAlertActionForIP(req.IP, "block")

	c.PureJSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("Block command sent for IP %s to %d agent(s)", req.IP, dispatched),
	})
}

// unblockIP 手动解封 IP
func (s *Server) unblockIP(c *gin.Context) {
	var req struct {
		IP      string `json:"ip" binding:"required"`
		Reason  string `json:"reason"`
		AgentID string `json:"agent_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	agents, err := s.resolveUnblockAgents(req.IP, req.AgentID)
	if err != nil {
		c.PureJSON(http.StatusConflict, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	dispatched, err := s.queueCommandForAgents("unblock_ip", req.IP, req.Reason, agents, proto.CommandType_UNBLOCK_IP)
	if err != nil {
		c.PureJSON(http.StatusConflict, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	s.logger.Info("Manual unblock command sent for IP: %s", req.IP)
	s.syncAlertActionForIP(req.IP, "unblock")

	c.PureJSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("Unblock command sent for IP %s to %d agent(s)", req.IP, dispatched),
	})
}

// batchBlockIP 批量封禁 IP
func (s *Server) batchBlockIP(c *gin.Context) {
	var req struct {
		IPs     []string `json:"ips" binding:"required"`
		Reason  string   `json:"reason"`
		AgentID string   `json:"agent_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	agents, err := s.resolveCommandAgents(req.AgentID)
	if err != nil {
		c.PureJSON(http.StatusConflict, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}
	count := 0
	realBlocked := 0
	for _, ip := range req.IPs {
		// 跳过白名单
		if s.engine.IsWhitelisted(ip) {
			s.logger.Warn("Skip batch block for whitelisted IP: %s", ip)
			continue
		}
		if state := s.getBlockState(ip); state == "active" || state == "pending" {
			s.logger.Info("Skip batch block for IP %s due to existing state: %s", ip, state)
			continue
		}

		if _, err := s.queueCommandForAgents("block_ip", ip, req.Reason, agents, proto.CommandType_BLOCK_IP); err != nil {
			s.logger.Warn("Skip batch block for IP %s: %v", ip, err)
			continue
		}
		count++
		realBlocked++
		s.syncAlertActionForIP(ip, "block")
	}

	c.PureJSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("Batch block command sent for %d IP(s)", realBlocked),
	})
}

// batchUnblockIP 批量解封 IP
func (s *Server) batchUnblockIP(c *gin.Context) {
	var req struct {
		IPs     []string `json:"ips" binding:"required"`
		Reason  string   `json:"reason"`
		AgentID string   `json:"agent_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	count := 0
	for _, ip := range req.IPs {
		agents, err := s.resolveUnblockAgents(ip, req.AgentID)
		if err != nil {
			s.logger.Warn("Skip batch unblock for IP %s: %v", ip, err)
			continue
		}
		if _, err := s.queueCommandForAgents("unblock_ip", ip, req.Reason, agents, proto.CommandType_UNBLOCK_IP); err != nil {
			s.logger.Warn("Skip batch unblock for IP %s: %v", ip, err)
			continue
		}
		count++
	}

	// 批量更新数据库状态
	if err := s.db.Model(&model.AlertLog{}).Where("source_ip IN ? AND action = ?", req.IPs, "block").Updates(map[string]interface{}{
		"action": "unblock",
		"status": 1,
	}).Error; err != nil {
		s.logger.Error("Failed to update alert logs for batch unblock: %v", err)
	}

	c.PureJSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("Batch unblock command sent for %d IP(s)", count),
	})
}

// getDashboardOverview 获取仪表盘概览
func (s *Server) getDashboardOverview(c *gin.Context) {
	var overview struct {
		TotalAlerts      int64   `json:"total_alerts"`
		TodayAlerts      int64   `json:"today_alerts"`
		CriticalAlerts   int64   `json:"critical_alerts"`
		HighAlerts       int64   `json:"high_alerts"`
		BlockedIPs       int64   `json:"blocked_ips"`
		PatchedConfigs   int64   `json:"patched_configs"`
		ActiveAgents     int     `json:"active_agents"`
		AverageRiskScore float64 `json:"average_risk_score"`
	}

	now := time.Now()
	startOfDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	s.db.Model(&model.AlertLog{}).Count(&overview.TotalAlerts)
	s.db.Model(&model.AlertLog{}).Where("created_at >= ?", startOfDay).Count(&overview.TodayAlerts)
	s.db.Model(&model.AlertLog{}).Where("severity = ?", "critical").Count(&overview.CriticalAlerts)
	s.db.Model(&model.AlertLog{}).Where("severity = ?", "high").Count(&overview.HighAlerts)
	s.db.Model(&model.AlertLog{}).Where("action = ?", "block").Count(&overview.BlockedIPs)
	s.db.Model(&model.AlertLog{}).Where("action = ?", "patch").Count(&overview.PatchedConfigs)

	// 计算平均风险评分
	var avgScore float64
	s.db.Model(&model.AlertLog{}).Select("AVG(risk_score)").Scan(&avgScore)
	overview.AverageRiskScore = avgScore

	c.PureJSON(http.StatusOK, gin.H{"data": overview})
}

// getAttackTrends 获取攻击趋势
func (s *Server) getAttackTrends(c *gin.Context) {
	days, _ := strconv.Atoi(c.DefaultQuery("days", "7"))
	trends, err := s.engine.GetAttackTrends(days)
	if err != nil {
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.PureJSON(http.StatusOK, gin.H{"data": trends})
}

// getTopAttackSources 获取 Top 攻击源
func (s *Server) getTopAttackSources(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
	sources, err := s.engine.GetTopAttackSources(limit)
	if err != nil {
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.PureJSON(http.StatusOK, gin.H{"data": sources})
}

// getSeverityDistribution 获取严重程度分布
func (s *Server) getSeverityDistribution(c *gin.Context) {
	distribution, err := s.engine.GetSeverityDistribution()
	if err != nil {
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.PureJSON(http.StatusOK, gin.H{"data": distribution})
}

// getActionStats 获取动作执行统计
func (s *Server) getActionStats(c *gin.Context) {
	stats, err := s.engine.GetActionStatistics()
	if err != nil {
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.PureJSON(http.StatusOK, gin.H{"data": stats})
}

// getAlertCorrelation 获取告警关联分析
func (s *Server) getAlertCorrelation(c *gin.Context) {
	alertID := c.Param("id")
	if alertID == "" {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": "alert id required"})
		return
	}

	group, err := s.engine.GetAlertCorrelation(alertID)
	if err != nil {
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.PureJSON(http.StatusOK, gin.H{"data": group})
}

// registerAgent Agent 注册接口 (供远程 Agent 调用)
func (s *Server) registerAgent(c *gin.Context) {
	var req struct {
		AgentID          string             `json:"agent_id" binding:"required"`
		Hostname         string             `json:"hostname"`
		IP               string             `json:"ip"`
		Name             string             `json:"name"`
		OSType           string             `json:"os_type"`
		ServiceInventory []agentServiceView `json:"service_inventory"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	now := time.Now()
	// 严格以 IP 为唯一标识进行维护
	var existingAgent model.AgentNode
	serviceInventoryJSON := encodeServiceInventory(req.ServiceInventory)
	result := s.db.Where("ip = ?", req.IP).First(&existingAgent)

	if result.Error != nil {
		// 未找到资产，创建新资产记录
		newAgent := &model.AgentNode{
			AgentID:          req.AgentID,
			Name:             req.Name,
			Hostname:         req.Hostname,
			IP:               req.IP,
			ServiceInventory: serviceInventoryJSON,
			Status:           1,
			LastSeenAt:       now,
			RegisteredAt:     now,
			CreatedAt:        now,
			UpdatedAt:        now,
		}
		if err := s.db.Create(newAgent).Error; err != nil {
			c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	} else {
		// 找到资产，更新现有记录 (保持 IP 不变)
		s.db.Model(&existingAgent).Updates(map[string]interface{}{
			"agent_id":          req.AgentID,
			"status":            1,
			"last_seen_at":      now,
			"hostname":          req.Hostname,
			"name":              req.Name,
			"service_inventory": serviceInventoryJSON,
			"updated_at":        now,
		})
	}

	s.syncAssetProfile(req.IP, req.Hostname, req.OSType, req.ServiceInventory, now)

	c.PureJSON(http.StatusOK, gin.H{
		"success":   true,
		"message":   "Agent registered/updated successfully",
		"agent_id":  req.AgentID,
		"master_ip": fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port),
	})
}

// deleteAgent 删除 Agent
func (s *Server) deleteAgent(c *gin.Context) {
	agentID := c.Param("id")
	if agentID == "" {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": "agent id required"})
		return
	}

	// 从数据库删除
	if err := s.db.Where("agent_id = ?", agentID).Delete(&model.AgentNode{}).Error; err != nil {
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.PureJSON(http.StatusOK, gin.H{"message": "Agent deleted"})
}

// unblockAgentIP 解除 Agent 的 IP 封禁
func (s *Server) unblockAgentIP(c *gin.Context) {
	agentID := c.Param("id")
	if agentID == "" {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": "agent id required"})
		return
	}

	// 获取 Agent 信息
	var agent model.AgentNode
	if err := s.db.Where("agent_id = ?", agentID).First(&agent).Error; err != nil {
		c.PureJSON(http.StatusNotFound, gin.H{"error": "Agent not found"})
		return
	}

	// 如果 Agent 在线，通过 gRPC 发送解封命令
	if s.grpcServer != nil && agent.Status == 1 {
		s.logger.Info("Would send unblock command to agent %s", agentID)
	}

	c.PureJSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("Unblock command sent to agent %s", agentID),
	})
}

// listWhitelist 获取白名单列表
func (s *Server) listWhitelist(c *gin.Context) {
	var whitelist []model.WhitelistIP
	if err := s.db.Order("created_at DESC").Find(&whitelist).Error; err != nil {
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.PureJSON(http.StatusOK, gin.H{"data": whitelist})
}

// addWhitelist 添加 IP 到白名单
func (s *Server) addWhitelist(c *gin.Context) {
	var req struct {
		IP     string `json:"ip" binding:"required"`
		Reason string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	whitelist := model.WhitelistIP{
		IP:     req.IP,
		Reason: req.Reason,
	}

	if err := s.db.Create(&whitelist).Error; err != nil {
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.PureJSON(http.StatusCreated, gin.H{"message": "IP added to whitelist", "data": whitelist})
}

// deleteWhitelist 从白名单中删除 IP
func (s *Server) deleteWhitelist(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	if err := s.db.Delete(&model.WhitelistIP{}, id).Error; err != nil {
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.PureJSON(http.StatusOK, gin.H{"message": "IP removed from whitelist"})
}

func buildAgentDetail(agent model.AgentNode) agentDetailView {
	return agentDetailView{
		AgentNode: agent,
		Services:  decodeServiceInventory(agent.ServiceInventory),
	}
}

func decodeServiceInventory(raw string) []agentServiceView {
	if strings.TrimSpace(raw) == "" {
		return []agentServiceView{}
	}

	var services []agentServiceView
	if err := json.Unmarshal([]byte(raw), &services); err != nil {
		return []agentServiceView{}
	}

	return services
}

func encodeServiceInventory(services []agentServiceView) string {
	if len(services) == 0 {
		return "[]"
	}

	data, err := json.Marshal(services)
	if err != nil {
		return "[]"
	}

	return string(data)
}

func (s *Server) syncAssetProfile(ip, hostname, osType string, services []agentServiceView, now time.Time) {
	if strings.TrimSpace(ip) == "" {
		return
	}

	serviceType := pickPrimaryServiceType(services)
	normalizedOSType := normalizeOSType(osType)

	var asset model.Asset
	result := s.db.Where("ip = ?", ip).First(&asset)
	if result.Error != nil {
		asset = model.Asset{
			IP:          ip,
			Hostname:    hostname,
			OSType:      normalizedOSType,
			ServiceType: serviceType,
			Status:      1,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		_ = s.db.Create(&asset).Error
		return
	}

	updates := map[string]interface{}{
		"status":     1,
		"updated_at": now,
	}
	if strings.TrimSpace(hostname) != "" {
		updates["hostname"] = hostname
	}
	if strings.TrimSpace(normalizedOSType) != "" {
		updates["os_type"] = normalizedOSType
	}
	if strings.TrimSpace(serviceType) != "" {
		updates["service_type"] = serviceType
	}

	_ = s.db.Model(&asset).Updates(updates).Error
}

func pickPrimaryServiceType(services []agentServiceView) string {
	if len(services) == 0 {
		return ""
	}

	ignore := map[string]struct{}{
		"":        {},
		"unknown": {},
	}

	preferred := []string{
		"tomcat",
		"spring-boot",
		"jenkins",
		"nacos",
		"nginx",
		"apache",
		"mysql",
		"postgresql",
		"redis",
		"elasticsearch",
		"kafka",
		"ssh",
		"java-service",
		"https",
		"http",
	}

	seen := make(map[string]struct{})
	for _, service := range services {
		name := strings.TrimSpace(strings.ToLower(service.Name))
		if _, skip := ignore[name]; skip {
			continue
		}
		seen[name] = struct{}{}
	}

	for _, candidate := range preferred {
		if _, ok := seen[candidate]; ok {
			return candidate
		}
	}

	for _, service := range services {
		name := strings.TrimSpace(service.Name)
		if name != "" && strings.ToLower(name) != "unknown" {
			return name
		}
	}

	return ""
}

func normalizeOSType(osType string) string {
	switch strings.ToLower(strings.TrimSpace(osType)) {
	case "linux":
		return "Linux"
	case "windows":
		return "Windows"
	case "darwin", "macos":
		return "macOS"
	default:
		return strings.TrimSpace(osType)
	}
}
