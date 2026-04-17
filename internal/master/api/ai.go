package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"security-response-system/internal/master/ai"
	"security-response-system/internal/master/core"
	sgrpc "security-response-system/internal/master/grpc"
	"security-response-system/internal/master/model"
	"security-response-system/internal/master/service"
	"security-response-system/internal/proto"
)

type aiDependencies struct {
	rule     *service.AIRuleService
	alert    *service.AIAlertService
	provider string
	enabled  bool
}

var serverAI sync.Map

func NewServerWithAI(
	cfg *model.Config,
	db *gorm.DB,
	redis interface{},
	engine *core.IntelligenceEngine,
	grpcServer *sgrpc.Server,
	aiRule *service.AIRuleService,
	aiAlert *service.AIAlertService,
) *Server {
	server := NewServer(cfg, db, redis, engine, grpcServer)
	serverAI.Store(server, aiDependencies{
		rule:     aiRule,
		alert:    aiAlert,
		provider: strings.TrimSpace(cfg.Master.AI.Provider),
		enabled:  cfg.Master.AI.Enabled,
	})

	alerts := server.router.Group("/api/alerts")
	{
		alerts.GET("/:id/ai-analysis", server.getAlertAIAnalysis)
	}

	aiGroup := server.router.Group("/api/ai")
	{
		aiGroup.GET("/status", server.getAIStatus)
		aiGroup.POST("/rules/generate", server.generateAIRule)
		aiGroup.GET("/rules/:id", server.getAIRuleTask)
		aiGroup.POST("/rules/:id/deploy", server.deployAIRule)
	}

	return server
}

func (s *Server) getAIDependencies() aiDependencies {
	if deps, ok := serverAI.Load(s); ok {
		return deps.(aiDependencies)
	}
	return aiDependencies{}
}

func (s *Server) getAlertAIAnalysis(c *gin.Context) {
	deps := s.getAIDependencies()
	if deps.alert == nil || !deps.alert.Enabled() {
		c.PureJSON(http.StatusServiceUnavailable, gin.H{"error": "ai alert analysis is disabled"})
		return
	}

	alertID := c.Param("id")
	if strings.TrimSpace(alertID) == "" {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": "alert id required"})
		return
	}

	insight, err := deps.alert.AnalyzeAlertByID(c.Request.Context(), alertID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.PureJSON(http.StatusNotFound, gin.H{"error": "alert not found"})
			return
		}
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.PureJSON(http.StatusOK, gin.H{"data": insight})
}

func (s *Server) getAIStatus(c *gin.Context) {
	deps := s.getAIDependencies()
	c.PureJSON(http.StatusOK, gin.H{
		"data": gin.H{
			"enabled":              deps.enabled,
			"provider":             emptyAIProvider(deps.provider),
			"rule_generation":      deps.rule != nil && deps.rule.Enabled(),
			"alert_analysis":       deps.alert != nil && deps.alert.Enabled(),
			"configuration_status": aiConfigStatus(deps),
		},
	})
}

func (s *Server) getAIRuleTask(c *gin.Context) {
	deps := s.getAIDependencies()
	if deps.rule == nil {
		c.PureJSON(http.StatusServiceUnavailable, gin.H{"error": "ai rule service is disabled"})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": "invalid rule task id"})
		return
	}

	task, err := deps.rule.GetTask(uint(id))
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.PureJSON(http.StatusNotFound, gin.H{"error": "rule task not found"})
			return
		}
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.PureJSON(http.StatusOK, gin.H{"data": task})
}

func (s *Server) generateAIRule(c *gin.Context) {
	deps := s.getAIDependencies()
	if deps.rule == nil || !deps.rule.Enabled() {
		c.PureJSON(http.StatusServiceUnavailable, gin.H{"error": "ai rule generation is disabled"})
		return
	}

	var req struct {
		SourceType    string `json:"source_type" binding:"required"`
		SourceContent string `json:"source_content" binding:"required"`
		TargetService string `json:"target_service"`
		ProtocolHint  string `json:"protocol_hint"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	task, err := deps.rule.GenerateCandidate(c.Request.Context(), ai.RuleGenInput{
		SourceType:    req.SourceType,
		SourceContent: req.SourceContent,
		TargetService: req.TargetService,
		ProtocolHint:  req.ProtocolHint,
	})
	if err != nil {
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.PureJSON(http.StatusOK, gin.H{"data": task})
}

func (s *Server) deployAIRule(c *gin.Context) {
	deps := s.getAIDependencies()
	if deps.rule == nil {
		c.PureJSON(http.StatusServiceUnavailable, gin.H{"error": "ai rule service is disabled"})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": "invalid rule task id"})
		return
	}

	task, err := deps.rule.GetTask(uint(id))
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.PureJSON(http.StatusNotFound, gin.H{"error": "rule task not found"})
			return
		}
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if strings.TrimSpace(task.GeneratedRule) == "" {
		c.PureJSON(http.StatusConflict, gin.H{"error": "rule task has no generated rule"})
		return
	}

	var req struct {
		AgentIDs          []string `json:"agent_ids"`
		ConfigPath        string   `json:"config_path"`
		ReloadCommandHint string   `json:"reload_command_hint"`
	}
	_ = c.ShouldBindJSON(&req)

	agents := s.grpcServer.GetConnectedAgents()
	if len(agents) == 0 {
		c.PureJSON(http.StatusConflict, gin.H{"error": "no connected agents"})
		return
	}

	targetSet := make(map[string]struct{})
	for _, id := range req.AgentIDs {
		id = strings.TrimSpace(id)
		if id != "" {
			targetSet[id] = struct{}{}
		}
	}

	dispatched := 0
	for _, agent := range agents {
		if len(targetSet) > 0 {
			if _, ok := targetSet[agent.AgentID]; !ok {
				continue
			}
		}

		cmd := &proto.CommandMessage{
			CommandId:      fmt.Sprintf("ai-rule-%d-%d", task.ID, time.Now().UnixNano()),
			Type:           proto.CommandType_PATCH_CONFIG,
			ConfigPath:     strings.TrimSpace(req.ConfigPath),
			MatchRegex:     "__DASRS_AI_RULE_DEPLOY__",
			ReplaceContent: task.GeneratedRule,
		}
		s.grpcServer.QueueCommand(agent.AgentID, cmd)
		dispatched++
	}

	if dispatched == 0 {
		c.PureJSON(http.StatusConflict, gin.H{"error": "no matching connected agents"})
		return
	}

	task.DeployStatus = "queued"
	task.TargetAgentCount = dispatched
	task.SuccessAgentCount = 0
	task.FailedAgentCount = 0
	task.DeployMessage = fmt.Sprintf("%s | master | queued to %d agent(s)", time.Now().Format(time.RFC3339), dispatched)
	task.UpdatedAt = time.Now()
	if err := s.db.Save(task).Error; err != nil {
		c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.PureJSON(http.StatusAccepted, gin.H{
		"message":             "rule deployment queued to agent command stream",
		"agent_count":         dispatched,
		"reload_command_hint": strings.TrimSpace(req.ReloadCommandHint),
		"data":                task,
	})
}

func aiConfigStatus(deps aiDependencies) string {
	switch {
	case !deps.enabled:
		return "disabled"
	case deps.rule != nil && deps.alert != nil:
		return "ready"
	default:
		return "incomplete"
	}
}

func emptyAIProvider(provider string) string {
	if strings.TrimSpace(provider) == "" {
		return "api"
	}
	return provider
}
