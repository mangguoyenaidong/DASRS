package model

import (
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
	ID            uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	AlertID       string    `gorm:"type:varchar(36);uniqueIndex;not null" json:"alert_id"`
	AgentID       string    `gorm:"type:varchar(100)" json:"agent_id"`
	SourceIP      string    `gorm:"type:varchar(45);index" json:"source_ip"`
	DestIP        string    `gorm:"type:varchar(45);index" json:"dest_ip"`
	SID           string    `gorm:"type:varchar(100);index" json:"sid"`
	SignatureName string    `gorm:"type:varchar(500)" json:"signature_name"`
	Severity      string    `gorm:"type:varchar(20);index" json:"severity"`
	Payload       string    `gorm:"type:text" json:"payload"`
	AssetInfo     string    `gorm:"type:text" json:"asset_info"`
	RiskScore     int       `gorm:"default:0" json:"risk_score"`
	Action        string    `gorm:"type:varchar(50)" json:"action"`
	Status        int       `gorm:"default:0;index" json:"status"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func (AlertLog) TableName() string {
	return "alert_logs"
}

// OperationLog stores all executed operations.
type OperationLog struct {
	ID              uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	CommandID       string    `gorm:"type:varchar(36);uniqueIndex;not null" json:"command_id"`
	AlertID         uint      `gorm:"index" json:"alert_id"`
	CommandType     string    `gorm:"type:varchar(50);index" json:"command_type"`
	Target          string    `gorm:"type:varchar(500)" json:"target"`
	Result          int       `gorm:"index" json:"result"`
	Message         string    `gorm:"type:text" json:"message"`
	ExecutionTimeMs int64     `json:"execution_time_ms"`
	CreatedAt       time.Time `json:"created_at"`
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

func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&AgentNode{},
		&Asset{},
		&Strategy{},
		&AlertLog{},
		&OperationLog{},
		&WhitelistIP{},
	)
}
