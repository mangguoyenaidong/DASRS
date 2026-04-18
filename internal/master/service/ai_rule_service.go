package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gorm.io/gorm"

	"security-response-system/internal/master/ai"
	"security-response-system/internal/master/model"
)

type AIRuleService struct {
	db        *gorm.DB
	provider  ai.Provider
	builder   *SuricataRuleBuilder
	validator *SuricataRuleValidator
	testing   ruleTestingConfig
}

type ruleTestingConfig struct {
	commandTemplate string
	successMatch    string
}

func NewAIRuleService(db *gorm.DB, provider ai.Provider, cfg *model.Config) *AIRuleService {
	testing := ruleTestingConfig{}
	if cfg != nil {
		testing.commandTemplate = strings.TrimSpace(cfg.Master.AI.Testing.CommandTemplate)
		testing.successMatch = strings.TrimSpace(cfg.Master.AI.Testing.SuccessMatch)
	}
	return &AIRuleService{
		db:        db,
		provider:  provider,
		builder:   NewSuricataRuleBuilder(),
		validator: NewSuricataRuleValidator(),
		testing:   testing,
	}
}

func (s *AIRuleService) Enabled() bool {
	return s != nil && s.provider != nil
}

func (s *AIRuleService) GenerateCandidate(ctx context.Context, input ai.RuleGenInput) (*model.AIRuleTask, error) {
	if !s.Enabled() {
		return nil, fmt.Errorf("ai rule generation is not enabled")
	}

	now := time.Now()
	task := &model.AIRuleTask{
		SourceType:    strings.TrimSpace(input.SourceType),
		SourceContent: input.SourceContent,
		TargetService: strings.TrimSpace(input.TargetService),
		ProtocolHint:  strings.TrimSpace(input.ProtocolHint),
		Status:        "generating",
		DeployStatus:  "pending",
		TestStatus:    "pending",
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := s.db.Create(task).Error; err != nil {
		return nil, err
	}

	result, err := s.provider.GenerateRule(ctx, input)
	if err != nil {
		task.Status = "failed"
		task.ValidationError = err.Error()
		task.UpdatedAt = time.Now()
		_ = s.db.Save(task).Error
		return nil, err
	}

	task.NormalizedSummary = result.Summary
	task.RawResponse = result.RawResponse

	ruleText, err := s.builder.Build(result, nextCandidateSID(task.ID))
	if err != nil {
		task.Status = "failed"
		task.ValidationError = err.Error()
		task.UpdatedAt = time.Now()
		_ = s.db.Save(task).Error
		return nil, err
	}

	if err := s.validator.Validate(ruleText); err != nil {
		task.Status = "invalid"
		task.GeneratedRule = ruleText
		task.ValidationError = err.Error()
		task.UpdatedAt = time.Now()
		_ = s.db.Save(task).Error
		return task, err
	}

	task.GeneratedRule = ruleText
	task.Status = "ready"
	task.TestStatus = "pending"
	task.ValidationError = ""
	task.UpdatedAt = time.Now()
	if err := s.db.Save(task).Error; err != nil {
		return nil, err
	}

	return task, nil
}

func (s *AIRuleService) GetTask(id uint) (*model.AIRuleTask, error) {
	var task model.AIRuleTask
	if err := s.db.First(&task, id).Error; err != nil {
		return nil, err
	}
	return &task, nil
}

func (s *AIRuleService) UpdateCandidate(taskID uint, ruleText, summary string) (*model.AIRuleTask, error) {
	task, err := s.GetTask(taskID)
	if err != nil {
		return nil, err
	}

	ruleText = strings.TrimSpace(ruleText)
	if ruleText == "" {
		return nil, fmt.Errorf("generated rule cannot be empty")
	}
	if err := s.validator.Validate(ruleText); err != nil {
		return nil, err
	}

	task.GeneratedRule = ruleText
	if strings.TrimSpace(summary) != "" {
		task.NormalizedSummary = strings.TrimSpace(summary)
	}
	task.Status = "ready"
	task.TestStatus = "pending"
	task.TestMessage = "candidate rule updated manually; re-test required"
	task.TestReport = ""
	task.DeployStatus = "pending"
	task.TargetAgentCount = 0
	task.SuccessAgentCount = 0
	task.FailedAgentCount = 0
	task.DeployMessage = ""
	task.ValidationError = ""
	task.UpdatedAt = time.Now()
	if err := s.db.Save(task).Error; err != nil {
		return nil, err
	}

	return task, nil
}

func (s *AIRuleService) TestCandidate(ctx context.Context, taskID uint, mode, sampleContent, samplePath, commandTemplate, successMatch string) (*model.AIRuleTask, error) {
	task, err := s.GetTask(taskID)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(task.GeneratedRule) == "" {
		return nil, fmt.Errorf("rule task has no generated rule")
	}

	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "master"
	}
	if mode != "master" {
		return nil, fmt.Errorf("test mode %q is not supported yet", mode)
	}

	task.TestStatus = "running"
	task.TestMessage = "rule test started"
	task.UpdatedAt = time.Now()
	if err := s.db.Save(task).Error; err != nil {
		return nil, err
	}

	if err := s.validator.Validate(task.GeneratedRule); err != nil {
		task.TestStatus = "failed"
		task.TestMessage = err.Error()
		task.TestReport = "validator rejected candidate rule"
		task.UpdatedAt = time.Now()
		_ = s.db.Save(task).Error
		return task, err
	}

	commandTemplate = strings.TrimSpace(commandTemplate)
	if commandTemplate == "" {
		commandTemplate = s.testing.commandTemplate
	}
	successMatch = strings.TrimSpace(successMatch)
	if successMatch == "" {
		successMatch = s.testing.successMatch
	}

	report := []string{"validator: passed"}
	if commandTemplate == "" {
		task.TestStatus = "passed"
		task.TestMessage = "validator passed; no test command configured"
		task.TestReport = strings.Join(report, "\n")
		task.Status = "tested"
		task.UpdatedAt = time.Now()
		if err := s.db.Save(task).Error; err != nil {
			return nil, err
		}
		return task, nil
	}

	tmpDir, err := os.MkdirTemp("", "dasrs-ai-rule-test-*")
	if err != nil {
		task.TestStatus = "failed"
		task.TestMessage = fmt.Sprintf("create temp dir: %v", err)
		task.TestReport = strings.Join(report, "\n")
		task.UpdatedAt = time.Now()
		_ = s.db.Save(task).Error
		return task, err
	}
	defer os.RemoveAll(tmpDir)

	ruleFile := filepath.Join(tmpDir, "candidate.rules")
	if err := os.WriteFile(ruleFile, []byte(strings.TrimSpace(task.GeneratedRule)+"\n"), 0644); err != nil {
		task.TestStatus = "failed"
		task.TestMessage = fmt.Sprintf("write rule file: %v", err)
		task.TestReport = strings.Join(report, "\n")
		task.UpdatedAt = time.Now()
		_ = s.db.Save(task).Error
		return task, err
	}

	sampleFile := strings.TrimSpace(samplePath)
	if strings.TrimSpace(sampleContent) != "" {
		sampleFile = filepath.Join(tmpDir, "sample.txt")
		if err := os.WriteFile(sampleFile, []byte(sampleContent), 0644); err != nil {
			task.TestStatus = "failed"
			task.TestMessage = fmt.Sprintf("write sample file: %v", err)
			task.TestReport = strings.Join(report, "\n")
			task.UpdatedAt = time.Now()
			_ = s.db.Save(task).Error
			return task, err
		}
	}

	rendered := strings.NewReplacer(
		"{{RULE_FILE}}", ruleFile,
		"{{RULE_SID}}", fmt.Sprintf("%d", nextCandidateSID(task.ID)),
		"{{SAMPLE_FILE}}", sampleFile,
	).Replace(commandTemplate)

	cmd := exec.CommandContext(ctx, "/bin/sh", "-lc", rendered)
	output, err := cmd.CombinedOutput()
	report = append(report, "command: "+rendered, "output:\n"+strings.TrimSpace(string(output)))
	if err != nil {
		task.TestStatus = "failed"
		task.TestMessage = fmt.Sprintf("test command failed: %v", err)
		task.TestReport = strings.Join(report, "\n")
		task.UpdatedAt = time.Now()
		_ = s.db.Save(task).Error
		return task, err
	}

	if successMatch != "" && !strings.Contains(string(output), successMatch) {
		err = fmt.Errorf("test output did not contain expected marker %q", successMatch)
		task.TestStatus = "failed"
		task.TestMessage = err.Error()
		task.TestReport = strings.Join(report, "\n")
		task.UpdatedAt = time.Now()
		_ = s.db.Save(task).Error
		return task, err
	}

	task.TestStatus = "passed"
	task.TestMessage = "rule test passed"
	task.TestReport = strings.Join(report, "\n")
	task.Status = "tested"
	task.UpdatedAt = time.Now()
	if err := s.db.Save(task).Error; err != nil {
		return nil, err
	}
	return task, nil
}
