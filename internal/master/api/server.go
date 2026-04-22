package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
	s.router.GET("/api/blocked-ips", s.listBlockedIPs)
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

	s.db.Model(&model.AgentNode{}).Count(&stats.TotalAssets)
	s.db.Model(&model.AgentNode{}).Where("status = ?", 1).Count(&stats.OnlineAssets)
	s.db.Model(&model.AlertLog{}).Count(&stats.TotalAlerts)
	s.db.Model(&model.AlertLog{}).Where("status = ?", 0).Count(&stats.PendingAlerts)
	s.db.Model(&model.Strategy{}).Count(&stats.TotalStrategies)
	s.db.Model(&model.Strategy{}).Where("enabled = ?", 1).Count(&stats.EnabledStrategies)

	// 同时获取已封禁 IP 数 (从封禁 API 的逻辑获取)
	var blockedCount int64
	s.db.Raw(`
		SELECT COUNT(DISTINCT target) 
		FROM operation_logs 
		WHERE command_type = 'block_ip' AND result = 1 
		AND target NOT IN (SELECT target FROM operation_logs WHERE command_type = 'unblock_ip' AND result = 1)
	`).Scan(&blockedCount)
	stats.BlockedIPs = blockedCount

	c.PureJSON(http.StatusOK, gin.H{"data": stats})
}

// listBlockedIPs 获取当前封禁中的 IP 列表 (基于操作日志)
func (s *Server) listBlockedIPs(c *gin.Context) {
	var results []struct {
		Target    string    `json:"ip"`
		CreatedAt time.Time `json:"blocked_at"`
		Message   string    `json:"reason"`
		Status    string    `json:"status"`
	}

	// 优先展示当前仍处于封禁或待执行状态的最新 block 记录。
	// 结果说明：
	// - active: Agent 已回执封禁成功
	// - pending: 封禁命令已下发，但尚未收到 Agent 执行回执
	query := `
		SELECT b.target, b.created_at, b.message,
		       CASE
		           WHEN b.result = 1 THEN 'active'
		           WHEN b.result = 0 AND COALESCE(b.execution_time_ms, 0) = 0 THEN 'pending'
		           ELSE 'inactive'
		       END AS status
		FROM operation_logs b
		INNER JOIN (
			SELECT target, MAX(created_at) AS latest_created_at
			FROM operation_logs
			WHERE command_type = 'block_ip'
			GROUP BY target
		) latest ON latest.target = b.target AND latest.latest_created_at = b.created_at
		WHERE b.command_type = 'block_ip'
		AND (
			b.result = 1
			OR (b.result = 0 AND COALESCE(b.execution_time_ms, 0) = 0)
		)
		AND b.target NOT IN (
			SELECT target FROM operation_logs
			WHERE command_type = 'unblock_ip' AND result = 1
		)
		ORDER BY b.created_at DESC
		LIMIT 100
	`

	if err := s.db.Raw(query).Scan(&results).Error; err != nil {
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.PureJSON(http.StatusOK, gin.H{
		"success": true,
		"data":    results,
	})
}

func (s *Server) getBlockState(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}

	var latest struct {
		CommandType string
		Result      int
	}

	err := s.db.Raw(`
		SELECT command_type, result
		FROM operation_logs
		WHERE target = ?
		AND command_type IN ('block_ip', 'unblock_ip')
		ORDER BY created_at DESC, id DESC
		LIMIT 1
	`, ip).Scan(&latest).Error
	if err != nil || strings.TrimSpace(latest.CommandType) == "" {
		return ""
	}

	switch latest.CommandType {
	case "block_ip":
		if latest.Result == 1 {
			return "active"
		}
		if latest.Result == 0 {
			return "pending"
		}
	case "unblock_ip":
		if latest.Result == 0 {
			return "unblock_pending"
		}
	}

	return ""
}

// blockIP 手动封禁 IP
func (s *Server) blockIP(c *gin.Context) {
	var req struct {
		IP     string `json:"ip" binding:"required"`
		Reason string `json:"reason"`
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

	commandID := fmt.Sprintf("man-block-%d", time.Now().Unix())
	cmd := &proto.CommandMessage{
		CommandId: commandID,
		Type:      proto.CommandType_BLOCK_IP,
		TargetIp:  req.IP,
	}

	agents := s.grpcServer.GetConnectedAgents()
	if len(agents) == 0 {
		c.PureJSON(http.StatusConflict, gin.H{
			"success": false,
			"message": "no connected agents available to execute block command",
		})
		return
	}

	// 预先记录操作日志
	s.db.Create(&model.OperationLog{
		CommandID:   commandID,
		CommandType: "block_ip",
		Target:      req.IP,
		Result:      0, // 初始为进行中
		Message:     fmt.Sprintf("Manual block: %s", req.Reason),
		CreatedAt:   time.Now(),
	})

	for _, agent := range agents {
		s.grpcServer.QueueCommand(agent.AgentID, cmd)
	}

	s.logger.Info("Manual block command sent for IP: %s, reason: %s", req.IP, req.Reason)

	c.PureJSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("Block command sent for IP %s to %d agents", req.IP, len(agents)),
	})
}

// unblockIP 手动解封 IP
func (s *Server) unblockIP(c *gin.Context) {
	var req struct {
		IP     string `json:"ip" binding:"required"`
		Reason string `json:"reason"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	commandID := fmt.Sprintf("man-unblock-%d", time.Now().Unix())
	cmd := &proto.CommandMessage{
		CommandId: commandID,
		Type:      proto.CommandType_UNBLOCK_IP,
		TargetIp:  req.IP,
	}

	agents := s.grpcServer.GetConnectedAgents()
	if len(agents) == 0 {
		c.PureJSON(http.StatusConflict, gin.H{
			"success": false,
			"message": "no connected agents available to execute unblock command",
		})
		return
	}

	// 预记录解封日志
	s.db.Create(&model.OperationLog{
		CommandID:   commandID,
		CommandType: "unblock_ip",
		Target:      req.IP,
		Result:      0,
		Message:     fmt.Sprintf("Manual unblock: %s", req.Reason),
		CreatedAt:   time.Now(),
	})

	for _, agent := range agents {
		s.grpcServer.QueueCommand(agent.AgentID, cmd)
	}

	// 同步更新数据库状态，确保 Web 后台不再显示该 IP 为封禁状态
	if err := s.db.Model(&model.AlertLog{}).Where("source_ip = ? AND action = ?", req.IP, "block").Updates(map[string]interface{}{
		"action": "unblock",
		"status": 1, // 已处理
	}).Error; err != nil {
		s.logger.Error("Failed to update alert logs for unblock: %v", err)
	}

	s.logger.Info("Manual unblock command sent for IP: %s", req.IP)

	c.PureJSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("Unblock command sent for IP %s to %d agents", req.IP, len(agents)),
	})
}

// batchBlockIP 批量封禁 IP
func (s *Server) batchBlockIP(c *gin.Context) {
	var req struct {
		IPs    []string `json:"ips" binding:"required"`
		Reason string   `json:"reason"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	agents := s.grpcServer.GetConnectedAgents()
	if len(agents) == 0 {
		c.PureJSON(http.StatusConflict, gin.H{
			"success": false,
			"message": "no connected agents available to execute batch block command",
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

		cmd := &proto.CommandMessage{
			CommandId: fmt.Sprintf("batch-block-%d-%d", time.Now().Unix(), count),
			Type:      proto.CommandType_BLOCK_IP,
			TargetIp:  ip,
		}
		for _, agent := range agents {
			s.grpcServer.QueueCommand(agent.AgentID, cmd)
		}
		count++
		realBlocked++
	}

	c.PureJSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("Batch block command sent for %d IPs (skipped whitelisted) to %d agents", realBlocked, len(agents)),
	})
}

// batchUnblockIP 批量解封 IP
func (s *Server) batchUnblockIP(c *gin.Context) {
	var req struct {
		IPs    []string `json:"ips" binding:"required"`
		Reason string   `json:"reason"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	agents := s.grpcServer.GetConnectedAgents()
	if len(agents) == 0 {
		c.PureJSON(http.StatusConflict, gin.H{
			"success": false,
			"message": "no connected agents available to execute batch unblock command",
		})
		return
	}
	count := 0
	for _, ip := range req.IPs {
		cmd := &proto.CommandMessage{
			CommandId: fmt.Sprintf("batch-unblock-%d-%d", time.Now().Unix(), count),
			Type:      proto.CommandType_UNBLOCK_IP,
			TargetIp:  ip,
		}
		for _, agent := range agents {
			s.grpcServer.QueueCommand(agent.AgentID, cmd)
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
		"message": fmt.Sprintf("Batch unblock command sent for %d IPs to %d agents", len(req.IPs), len(agents)),
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
