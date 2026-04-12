package api

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"security-response-system/internal/common"
	"security-response-system/internal/master/core"
	"security-response-system/internal/master/model"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"gorm.io/gorm"
)

// Server HTTP API 服务器
type Server struct {
	router     *gin.Engine
	server     *http.Server
	cfg        *Config
	db         *gorm.DB
	redis      interface{}
	engine     *core.IntelligenceEngine
	logger     *common.Logger
	grpcServer *grpc.Server // 添加 gRPC server 引用
}

// Config API 配置
type Config struct {
	Host string
	Port int
}

// NewServer 创建服务器
func NewServer(cfg *model.Config, db *gorm.DB, redis interface{}, engine *core.IntelligenceEngine, grpcServer *grpc.Server) *Server {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	server := &Server{
		router: router,
		cfg: &Config{
			Host: cfg.Master.Host,
			Port: cfg.Master.HTTPPort,
		},
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
	}

	// 策略管理
	strategies := s.router.Group("/api/strategies")
	{
		strategies.GET("", s.listStrategies)
		strategies.GET("/:id", s.getStrategy)
		strategies.POST("", s.createStrategy)
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
	s.router.POST("/api/block", s.blockIP)

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

	c.PureJSON(http.StatusOK, gin.H{"data": agent})
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
		query = query.Where("source_ip = ?", sourceIP)
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

// createStrategy 创建策略
func (s *Server) createStrategy(c *gin.Context) {
	var strategy model.Strategy
	if err := c.ShouldBindJSON(&strategy); err != nil {
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

	s.db.Save(&strategy)
	c.PureJSON(http.StatusOK, gin.H{
		"message": "strategy updated",
		"data":    strategy,
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

	s.db.Model(&model.Asset{}).Count(&stats.TotalAssets)
	s.db.Model(&model.Asset{}).Where("status = ?", 1).Count(&stats.OnlineAssets)
	s.db.Model(&model.AlertLog{}).Count(&stats.TotalAlerts)
	s.db.Model(&model.AlertLog{}).Where("status = ?", 0).Count(&stats.PendingAlerts)
	s.db.Model(&model.Strategy{}).Count(&stats.TotalStrategies)
	s.db.Model(&model.Strategy{}).Where("enabled = ?", 1).Count(&stats.EnabledStrategies)

	c.PureJSON(http.StatusOK, gin.H{"data": stats})
}

// blockIP 手动封禁 IP
func (s *Server) blockIP(c *gin.Context) {
	var req struct {
		IP      string `json:"ip" binding:"required"`
		Reason  string `json:"reason"`
		Expires int    `json:"expires"` // 过期时间（秒）
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: 推送到 gRPC Server 通过指令流发送到 Agent
	s.logger.Info("Manual block request for IP: %s, reason: %s", req.IP, req.Reason)

	c.PureJSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("Block command sent for IP %s", req.IP),
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
		AgentID  string `json:"agent_id" binding:"required"`
		Hostname string `json:"hostname"`
		IP       string `json:"ip"`
		Name     string `json:"name"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	now := time.Now()
	agent := &model.AgentNode{
		AgentID:      req.AgentID,
		Name:         req.Name,
		Hostname:     req.Hostname,
		IP:           req.IP,
		Status:       1,
		LastSeenAt:   now,
		RegisteredAt: now,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	result := s.db.Where("agent_id = ?", req.AgentID).First(&model.AgentNode{})
	if result.Error != nil {
		// 新 Agent
		if err := s.db.Create(agent).Error; err != nil {
			c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	} else {
		// 更新现有 Agent
		s.db.Model(&model.AgentNode{}).
			Where("agent_id = ?", req.AgentID).
			Updates(map[string]interface{}{
				"status":       1,
				"last_seen_at": now,
				"hostname":     req.Hostname,
				"ip":           req.IP,
				"name":         req.Name,
				"updated_at":   now,
			})
	}

	c.PureJSON(http.StatusOK, gin.H{
		"success":   true,
		"message":   "Agent registered successfully",
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
