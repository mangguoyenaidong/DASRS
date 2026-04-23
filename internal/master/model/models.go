package model

import (
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

// AgentNode stores registered Agent node metadata.
type AgentNode struct {
	ID               uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	AgentID          string    `gorm:"type:varchar(100);uniqueIndex;not null" json:"agent_id"`
	Name             string    `gorm:"type:varchar(255)" json:"name"`
	Hostname         string    `gorm:"type:varchar(255)" json:"hostname"`
	IP               string    `gorm:"type:varchar(45)" json:"ip"`
	ServiceInventory string    `gorm:"type:text" json:"service_inventory"`
	Status           int       `gorm:"default:1" json:"status"`
	LastSeenAt       time.Time `json:"last_seen_at"`
	RegisteredAt     time.Time `json:"registered_at"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

func (AgentNode) TableName() string {
	return "agent_nodes"
}

// Asset stores protected host metadata.
type Asset struct {
	ID          uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	IP          string    `gorm:"type:varchar(45);uniqueIndex;not null" json:"ip"`
	Hostname    string    `gorm:"type:varchar(255)" json:"hostname"`
	OSType      string    `gorm:"type:varchar(100)" json:"os_type"`
	ServiceType string    `gorm:"type:varchar(100)" json:"service_type"`
	Status      int       `gorm:"default:1" json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (Asset) TableName() string {
	return "assets"
}

// Strategy stores config remediation strategies.
type Strategy struct {
	ID             uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	SID            string    `gorm:"type:varchar(100);not null;index" json:"sid"`
	TargetFile     string    `gorm:"type:varchar(500)" json:"target_file"`
	MatchRegex     string    `gorm:"type:text" json:"match_regex"`
	ReplaceContent string    `gorm:"type:text" json:"replace_content"`
	Description    string    `gorm:"type:varchar(500)" json:"description"`
	Enabled        int       `gorm:"default:1" json:"enabled"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func (Strategy) TableName() string {
	return "strategies"
}

// AlertLog stores all collected alerts.
type AlertLog struct {
	ID             uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	AlertID        string    `gorm:"type:varchar(36);uniqueIndex;not null" json:"alert_id"`
	AgentID        string    `gorm:"type:varchar(100)" json:"agent_id"`
	SourceIP       string    `gorm:"type:varchar(45);index" json:"source_ip"`
	DestIP         string    `gorm:"type:varchar(45);index" json:"dest_ip"`
	SID            string    `gorm:"type:varchar(100);index" json:"sid"`
	SignatureName  string    `gorm:"type:varchar(500)" json:"signature_name"`
	Severity       string    `gorm:"type:varchar(20);index" json:"severity"`
	Payload        string    `gorm:"type:text" json:"payload"`
	AssetInfo      string    `gorm:"type:text" json:"asset_info"`
	RiskScore      int       `gorm:"default:0" json:"risk_score"`
	AttackCategory string    `gorm:"type:varchar(50);index" json:"attack_category"`
	Action         string    `gorm:"type:varchar(50)" json:"action"`
	Status         int       `gorm:"default:0;index" json:"status"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func (AlertLog) TableName() string {
	return "alert_logs"
}

// OperationLog stores all executed operations.
type OperationLog struct {
	ID              uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	CommandID       string    `gorm:"type:varchar(128);uniqueIndex;not null" json:"command_id"`
	AgentID         string    `gorm:"type:varchar(100);index" json:"agent_id"`
	AlertID         uint      `gorm:"index" json:"alert_id"`
	CommandType     string    `gorm:"type:varchar(50);index" json:"command_type"`
	Target          string    `gorm:"type:varchar(500)" json:"target"`
	Result          int       `gorm:"index" json:"result"`
	Message         string    `gorm:"type:text" json:"message"`
	ExecutionTimeMs int64     `json:"execution_time_ms"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func (OperationLog) TableName() string {
	return "operation_logs"
}

// WhitelistIP stores trusted IP entries.
type WhitelistIP struct {
	ID        uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	IP        string    `gorm:"type:varchar(45);uniqueIndex;not null" json:"ip"`
	Reason    string    `gorm:"type:varchar(255)" json:"reason"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (WhitelistIP) TableName() string {
	return "whitelist_ips"
}

// AIRuleTask stores AI-assisted rule generation requests and outputs.
type AIRuleTask struct {
	ID                uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	SourceType        string    `gorm:"type:varchar(50);index" json:"source_type"`
	SourceContent     string    `gorm:"type:longtext" json:"source_content"`
	TargetService     string    `gorm:"type:varchar(100)" json:"target_service"`
	ProtocolHint      string    `gorm:"type:varchar(50)" json:"protocol_hint"`
	NormalizedSummary string    `gorm:"type:text" json:"normalized_summary"`
	GeneratedRule     string    `gorm:"type:longtext" json:"generated_rule"`
	RawResponse       string    `gorm:"type:longtext" json:"raw_response"`
	Status            string    `gorm:"type:varchar(50);index" json:"status"`
	DeployStatus      string    `gorm:"type:varchar(50);index" json:"deploy_status"`
	TestStatus        string    `gorm:"type:varchar(50);index" json:"test_status"`
	TargetAgentCount  int       `gorm:"default:0" json:"target_agent_count"`
	SuccessAgentCount int       `gorm:"default:0" json:"success_agent_count"`
	FailedAgentCount  int       `gorm:"default:0" json:"failed_agent_count"`
	DeployMessage     string    `gorm:"type:longtext" json:"deploy_message"`
	TestMessage       string    `gorm:"type:text" json:"test_message"`
	TestReport        string    `gorm:"type:longtext" json:"test_report"`
	ValidationError   string    `gorm:"type:text" json:"validation_error"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

func (AIRuleTask) TableName() string {
	return "ai_rule_tasks"
}

// AlertAIInsight stores AI-generated alert interpretation results.
type AlertAIInsight struct {
	ID                uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	AlertID           string    `gorm:"type:varchar(36);uniqueIndex;not null" json:"alert_id"`
	AlertLogID        uint      `gorm:"index" json:"alert_log_id"`
	Summary           string    `gorm:"type:text" json:"summary"`
	AttackType        string    `gorm:"type:varchar(120)" json:"attack_type"`
	RiskReason        string    `gorm:"type:text" json:"risk_reason"`
	ImpactScope       string    `gorm:"type:text" json:"impact_scope"`
	EvidencePoints    string    `gorm:"type:text" json:"evidence_points"`
	SuspiciousPath    string    `gorm:"type:text" json:"suspicious_path"`
	SuspiciousParams  string    `gorm:"type:text" json:"suspicious_params"`
	CommandFragments  string    `gorm:"type:text" json:"command_fragments"`
	OperatorAdvice    string    `gorm:"type:text" json:"operator_advice"`
	RecommendedAction string    `gorm:"type:varchar(50)" json:"recommended_action"`
	Confidence        float64   `json:"confidence"`
	RawResponse       string    `gorm:"type:longtext" json:"raw_response"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

func (AlertAIInsight) TableName() string {
	return "alert_ai_insights"
}

func AutoMigrate(db *gorm.DB) error {
	if err := db.AutoMigrate(
		&AgentNode{},
		&Asset{},
		&Strategy{},
		&AlertLog{},
		&OperationLog{},
		&WhitelistIP{},
		&AIRuleTask{},
		&AlertAIInsight{},
	); err != nil {
		return err
	}

	compatSQL := []string{
		"ALTER TABLE operation_logs MODIFY COLUMN command_id VARCHAR(128) NOT NULL",
		"ALTER TABLE operation_logs ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP",
		"ALTER TABLE alert_logs MODIFY COLUMN attack_category VARCHAR(50) NULL",
	}
	for _, stmt := range compatSQL {
		if err := db.Exec(stmt).Error; err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
			return fmt.Errorf("schema compatibility migration failed: %w", err)
		}
	}

	return nil
}
