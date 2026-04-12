package model

import (
	"time"

	"gorm.io/gorm"
)

// AgentNode Agent 节点表
type AgentNode struct {
	ID           uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	AgentID      string    `gorm:"type:varchar(100);uniqueIndex;not null" json:"agent_id"` // 唯一标识
	Name         string    `gorm:"type:varchar(255)" json:"name"`                          // 节点名称
	Hostname     string    `gorm:"type:varchar(255)" json:"hostname"`                      // 主机名
	IP           string    `gorm:"type:varchar(45)" json:"ip"`                             // IP 地址
	Status       int       `gorm:"default:1" json:"status"`                                // 1: 在线, 0: 离线
	LastSeenAt   time.Time `json:"last_seen_at"`                                           // 最后活动时间
	RegisteredAt time.Time `json:"registered_at"`                                          // 注册时间
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// TableName 指定表名
func (AgentNode) TableName() string {
	return "agent_nodes"
}

// Asset 资产表 - 存储受保护的服务器资产信息
type Asset struct {
	ID         uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	IP         string    `gorm:"type:varchar(45);uniqueIndex;not null" json:"ip"`
	Hostname   string    `gorm:"type:varchar(255)" json:"hostname"`
	OSType     string    `gorm:"type:varchar(100)" json:"os_type"`         // 操作系统类型
	ServiceType string   `gorm:"type:varchar(100)" json:"service_type"`    // 服务类型: Nginx, IIS, Apache 等
	Status     int       `gorm:"default:1" json:"status"`                  // 1: 在线, 0: 离线
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// TableName 指定表名
func (Asset) TableName() string {
	return "assets"
}

// Strategy 策略表 - 存储配置文件修复策略
type Strategy struct {
	ID            uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	SID           string    `gorm:"type:varchar(100);not null;index" json:"sid"`          // Suricata Signature ID
	TargetFile    string    `gorm:"type:varchar(500)" json:"target_file"`                  // 目标配置文件路径
	MatchRegex    string    `gorm:"type:text" json:"match_regex"`                          // 匹配正则表达式
	ReplaceContent string   `gorm:"type:text" json:"replace_content"`                      // 替换内容
	Description   string    `gorm:"type:varchar(500)" json:"description"`
	Enabled       int       `gorm:"default:1" json:"enabled"`                              // 1: 启用, 0: 禁用
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// TableName 指定表名
func (Strategy) TableName() string {
	return "strategies"
}

// AlertLog 告警日志表 - 存储所有收到的告警
type AlertLog struct {
	ID            uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	AlertID       string    `gorm:"type:varchar(36);uniqueIndex;not null" json:"alert_id"` // UUID
	AgentID       string    `gorm:"type:varchar(100)" json:"agent_id"`
	SourceIP      string    `gorm:"type:varchar(45);index" json:"source_ip"`
	SID           string    `gorm:"type:varchar(100);index" json:"sid"`
	SignatureName string    `gorm:"type:varchar(500)" json:"signature_name"`
	Severity      string    `gorm:"type:varchar(20);index" json:"severity"` // low, medium, high, critical
	Payload       string    `gorm:"type:text" json:"payload"`
	AssetInfo     string    `gorm:"type:text" json:"asset_info"`
	RiskScore     int       `gorm:"default:0" json:"risk_score"` // 风险评分
	Action        string    `gorm:"type:varchar(50)" json:"action"`      // block, patch, ignore
	Status        int       `gorm:"default:0;index" json:"status"`       // 0: 待处理, 1: 已处理, 2: 已忽略
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// TableName 指定表名
func (AlertLog) TableName() string {
	return "alert_logs"
}

// OperationLog 操作日志表 - 存储所有执行的操作
type OperationLog struct {
	ID              uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	CommandID       string    `gorm:"type:varchar(36);uniqueIndex;not null" json:"command_id"`
	AlertID         uint      `gorm:"index" json:"alert_id"`
	CommandType     string    `gorm:"type:varchar(50);index" json:"command_type"` // block_ip, unblock_ip, patch_config
	Target          string    `gorm:"type:varchar(500)" json:"target"`
	Result          int       `gorm:"index" json:"result"`                 // 0: 失败, 1: 成功
	Message         string    `gorm:"type:text" json:"message"`
	ExecutionTimeMs int64     `json:"execution_time_ms"`            // 执行耗时(毫秒)
	CreatedAt       time.Time `json:"created_at"`
}

// TableName 指定表名
func (OperationLog) TableName() string {
	return "operation_logs"
}

// WhitelistIP 白名单 IP 表
type WhitelistIP struct {
	ID        uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	IP        string    `gorm:"type:varchar(45);uniqueIndex;not null" json:"ip"`
	Reason    string    `gorm:"type:varchar(255)" json:"reason"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TableName 指定表名
func (WhitelistIP) TableName() string {
	return "whitelist_ips"
}

// AutoMigrate 自动迁移数据库表结构
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
