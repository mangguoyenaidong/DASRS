-- DASRS 数据库初始化脚本
-- 创建数据库: security

USE security;

-- 资产表
CREATE TABLE IF NOT EXISTS assets (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(45) NOT NULL UNIQUE,
    hostname VARCHAR(255),
    os_type VARCHAR(100),          -- 操作系统类型
    service_type VARCHAR(100),     -- 服务类型: Nginx, IIS, Apache 等
    status TINYINT DEFAULT 1,      -- 1: 在线, 0: 离线
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_ip (ip),
    INDEX idx_service_type (service_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 策略表
CREATE TABLE IF NOT EXISTS strategies (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    sid VARCHAR(100) NOT NULL,     -- Suricata Signature ID
    target_file VARCHAR(500),      -- 目标配置文件路径
    match_regex TEXT,              -- 匹配正则表达式
    replace_content TEXT,          -- 替换内容
    description VARCHAR(500),
    enabled TINYINT DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_sid (sid),
    INDEX idx_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 告警日志表
CREATE TABLE IF NOT EXISTS alert_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    alert_id VARCHAR(36) NOT NULL UNIQUE,  -- UUID
    agent_id VARCHAR(100),
    source_ip VARCHAR(45) NOT NULL,
    sid VARCHAR(100),
    signature_name VARCHAR(500),
    severity VARCHAR(20),          -- low, medium, high, critical
    payload TEXT,
    asset_info TEXT,
    risk_score INT DEFAULT 0,      -- 风险评分
    action VARCHAR(50),            -- block, patch, ignore
    status TINYINT DEFAULT 0,      -- 0: 待处理, 1: 已处理, 2: 已忽略
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_source_ip (source_ip),
    INDEX idx_severity (severity),
    INDEX idx_status (status),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 操作日志表
CREATE TABLE IF NOT EXISTS operation_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    command_id VARCHAR(36) NOT NULL UNIQUE,
    alert_id BIGINT,
    command_type VARCHAR(50),      -- block_ip, unblock_ip, patch_config
    target VARCHAR(500),
    result TINYINT,                -- 0: 失败, 1: 成功
    message TEXT,
    execution_time_ms BIGINT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_alert_id (alert_id),
    INDEX idx_command_type (command_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 插入示例数据
INSERT INTO assets (ip, hostname, os_type, service_type) VALUES
('192.168.1.100', 'web-server-01', 'Linux', 'Nginx'),
('192.168.1.101', 'web-server-02', 'Linux', 'Nginx'),
('192.168.1.102', 'win-server-01', 'Windows', 'IIS');

INSERT INTO strategies (sid, target_file, match_regex, replace_content, description) VALUES
('2000001', '/etc/nginx/sites-available/default', 'location /admin', 'location /admin\n    allow 10.0.0.0/8;\n    deny all;', '限制 admin 访问'),
('2000002', '/etc/nginx/nginx.conf', 'client_max_body_size', 'client_max_body_size 1m;', '限制请求体大小');
