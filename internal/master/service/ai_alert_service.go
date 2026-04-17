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

func (s *AIAlertService) AnalyzeAlertByID(ctx context.Context, alertID string) (*model.AlertAIInsight, error) {
	if !s.Enabled() {
		return nil, fmt.Errorf("ai alert analysis is not enabled")
	}

	var cached model.AlertAIInsight
	if err := s.db.Where("alert_id = ?", alertID).First(&cached).Error; err == nil {
		return &cached, nil
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
		Limit(5).
		Find(&related).Error

	input := ai.AlertAnalysisInput{
		AlertID:         alert.AlertID,
		SID:             alert.SID,
		SignatureName:   alert.SignatureName,
		Severity:        alert.Severity,
		SourceIP:        alert.SourceIP,
		DestIP:          alert.DestIP,
		Payload:         alert.Payload,
		AssetInfo:       alert.AssetInfo,
		AssetService:    asset.ServiceType,
		AssetOS:         asset.OSType,
		RiskScore:       alert.RiskScore,
		RuleAction:      alert.Action,
		RuleReason:      alert.AssetInfo,
		RecentAlertText: buildRecentAlertText(related),
	}

	result, err := s.provider.AnalyzeAlert(ctx, input)
	if err != nil {
		return nil, err
	}

	insight := &model.AlertAIInsight{
		AlertID:           alert.AlertID,
		AlertLogID:        alert.ID,
		Summary:           result.Summary,
		AttackType:        result.AttackType,
		RiskReason:        result.RiskReason,
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
