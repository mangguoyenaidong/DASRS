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

type AIRuleService struct {
	db        *gorm.DB
	provider  ai.Provider
	builder   *SuricataRuleBuilder
	validator *SuricataRuleValidator
}

func NewAIRuleService(db *gorm.DB, provider ai.Provider) *AIRuleService {
	return &AIRuleService{
		db:        db,
		provider:  provider,
		builder:   NewSuricataRuleBuilder(),
		validator: NewSuricataRuleValidator(),
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

func (s *AIRuleService) UpdateDeployResult(taskID uint, agentID string, success bool, message string) error {
	var task model.AIRuleTask
	if err := s.db.First(&task, taskID).Error; err != nil {
		return err
	}

	status := "failed"
	if success {
		status = "deployed"
	}

	entry := fmt.Sprintf("%s | %s | %s", time.Now().Format(time.RFC3339), agentID, strings.TrimSpace(message))
	if strings.TrimSpace(task.DeployMessage) == "" {
		task.DeployMessage = entry
	} else {
		task.DeployMessage = task.DeployMessage + "\n" + entry
	}
	task.DeployStatus = status
	task.UpdatedAt = time.Now()

	return s.db.Save(&task).Error
}
