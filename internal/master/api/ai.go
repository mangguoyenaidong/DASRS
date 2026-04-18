package api

import (
	"encoding/json"
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
	rule                *service.AIRuleService
	alert               *service.AIAlertService
	provider            string
	enabled             bool
	demoMode            bool
	blockThreshold      int
	repairThreshold     int
	demoBlockThreshold  int
	demoRepairThreshold int
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
		rule:                aiRule,
		alert:               aiAlert,
		provider:            strings.TrimSpace(cfg.Master.AI.Provider),
		enabled:             cfg.Master.AI.Enabled,
		demoMode:            cfg.Master.Intelligence.DemoMode,
		blockThreshold:      cfg.Master.Intelligence.BlockThreshold,
		repairThreshold:     cfg.Master.Intelligence.RepairThreshold,
		demoBlockThreshold:  cfg.Master.Intelligence.DemoBlockThreshold,
		demoRepairThreshold: cfg.Master.Intelligence.DemoRepairThreshold,
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
		aiGroup.PUT("/rules/:id", server.updateAIRule)
		aiGroup.POST("/rules/:id/test", server.testAIRule)
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

	force := strings.EqualFold(strings.TrimSpace(c.Query("force")), "true")
	insight, err := deps.alert.AnalyzeAlertByID(c.Request.Context(), alertID, force)
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
			"enabled":               deps.enabled,
			"provider":              emptyAIProvider(deps.provider),
			"rule_generation":       deps.rule != nil && deps.rule.Enabled(),
			"alert_analysis":        deps.alert != nil && deps.alert.Enabled(),
			"configuration_status":  aiConfigStatus(deps),
			"testing_required":      true,
			"demo_mode":             deps.demoMode,
			"block_threshold":       deps.blockThreshold,
			"repair_threshold":      deps.repairThreshold,
			"demo_block_threshold":  deps.demoBlockThreshold,
			"demo_repair_threshold": deps.demoRepairThreshold,
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

func (s *Server) updateAIRule(c *gin.Context) {
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

	var req struct {
		GeneratedRule string `json:"generated_rule" binding:"required"`
		Summary       string `json:"summary"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.PureJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	task, err := deps.rule.UpdateCandidate(uint(id), req.GeneratedRule, req.Summary)
	if err != nil {
		c.PureJSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}

	c.PureJSON(http.StatusOK, gin.H{"message": "candidate rule updated", "data": task})
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
		Force             bool     `json:"force"`
	}
	_ = c.ShouldBindJSON(&req)

	if task.TestStatus != "passed" && !req.Force {
		c.PureJSON(http.StatusConflict, gin.H{
			"error":       "rule task must pass testing before deployment",
			"test_status": task.TestStatus,
			"data":        task,
		})
		return
	}

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

func (s *Server) testAIRule(c *gin.Context) {
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

	var req struct {
		Mode            string   `json:"mode"`
		AgentIDs        []string `json:"agent_ids"`
		SampleContent   string   `json:"sample_content"`
		SamplePath      string   `json:"sample_path"`
		CommandTemplate string   `json:"command_template"`
		SuccessMatch    string   `json:"success_match"`
	}
	_ = c.ShouldBindJSON(&req)

	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "master"
	}

	if mode == "agent" {
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

		agents := s.grpcServer.GetConnectedAgents()
		if len(agents) == 0 {
			c.PureJSON(http.StatusConflict, gin.H{"error": "no connected agents"})
			return
		}

		targetSet := make(map[string]struct{})
		for _, agentID := range req.AgentIDs {
			agentID = strings.TrimSpace(agentID)
			if agentID != "" {
				targetSet[agentID] = struct{}{}
			}
		}

		var selected *sgrpc.AgentInfo
		for _, agent := range agents {
			if len(targetSet) == 0 {
				selected = agent
				break
			}
			if _, ok := targetSet[agent.AgentID]; ok {
				selected = agent
				break
			}
		}
		if selected == nil {
			c.PureJSON(http.StatusConflict, gin.H{"error": "no matching connected test agent"})
			return
		}

		payload, err := json.Marshal(gin.H{
			"rule_content":     task.GeneratedRule,
			"command_template": strings.TrimSpace(req.CommandTemplate),
		})
		if err != nil {
			c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		cmd := &proto.CommandMessage{
			CommandId:      fmt.Sprintf("ai-rule-test-%d-%d", task.ID, time.Now().UnixNano()),
			Type:           proto.CommandType_PATCH_CONFIG,
			MatchRegex:     "__DASRS_AI_RULE_TEST__",
			ReplaceContent: string(payload),
		}
		s.grpcServer.QueueCommand(selected.AgentID, cmd)

		task.TestStatus = "queued"
		task.TestMessage = fmt.Sprintf("queued to test agent %s", selected.AgentID)
		task.TestReport = fmt.Sprintf("%s | master | queued agent test on %s", time.Now().Format(time.RFC3339), selected.AgentID)
		task.UpdatedAt = time.Now()
		if err := s.db.Save(task).Error; err != nil {
			c.PureJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.PureJSON(http.StatusAccepted, gin.H{
			"message":  "agent-side rule test queued",
			"agent_id": selected.AgentID,
			"data":     task,
		})
		return
	}

	task, err := deps.rule.TestCandidate(
		c.Request.Context(),
		uint(id),
		mode,
		req.SampleContent,
		req.SamplePath,
		req.CommandTemplate,
		req.SuccessMatch,
	)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not supported yet") {
			status = http.StatusNotImplemented
		} else if strings.Contains(err.Error(), "did not contain expected marker") || strings.Contains(err.Error(), "validator") {
			status = http.StatusUnprocessableEntity
		}
		c.PureJSON(status, gin.H{"error": err.Error(), "data": task})
		return
	}

	c.PureJSON(http.StatusOK, gin.H{"message": "rule test completed", "data": task})
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
