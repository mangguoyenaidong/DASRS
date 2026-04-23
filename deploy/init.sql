-- DASRS database bootstrap
CREATE DATABASE IF NOT EXISTS security
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE security;

CREATE TABLE IF NOT EXISTS assets (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(45) NOT NULL UNIQUE,
    hostname VARCHAR(255),
    os_type VARCHAR(100),
    service_type VARCHAR(100),
    status TINYINT DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_ip (ip),
    INDEX idx_service_type (service_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS strategies (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    sid VARCHAR(100) NOT NULL,
    target_file VARCHAR(500),
    match_regex TEXT,
    replace_content TEXT,
    description VARCHAR(500),
    enabled TINYINT DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_sid (sid),
    INDEX idx_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS alert_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    alert_id VARCHAR(36) NOT NULL UNIQUE,
    agent_id VARCHAR(100),
    source_ip VARCHAR(45) NOT NULL,
    dest_ip VARCHAR(45),
    sid VARCHAR(100),
    signature_name VARCHAR(500),
    severity VARCHAR(20),
    payload TEXT,
    asset_info TEXT,
    risk_score INT DEFAULT 0,
    action VARCHAR(50),
    status TINYINT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_source_ip (source_ip),
    INDEX idx_dest_ip (dest_ip),
    INDEX idx_severity (severity),
    INDEX idx_status (status),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS operation_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    command_id VARCHAR(36) NOT NULL UNIQUE,
    agent_id VARCHAR(100),
    alert_id BIGINT,
    command_type VARCHAR(50),
    target VARCHAR(500),
    result TINYINT,
    message TEXT,
    execution_time_ms BIGINT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_agent_id (agent_id),
    INDEX idx_alert_id (alert_id),
    INDEX idx_command_type (command_type),
    INDEX idx_result (result)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO assets (ip, hostname, os_type, service_type, status) VALUES
('192.168.1.100', 'web-server-01', 'Linux', 'Nginx', 1),
('192.168.1.101', 'web-server-02', 'Linux', 'Nginx', 1),
('192.168.1.102', 'win-server-01', 'Windows', 'IIS', 1)
ON DUPLICATE KEY UPDATE
    hostname = VALUES(hostname),
    os_type = VALUES(os_type),
    service_type = VALUES(service_type),
    status = VALUES(status);

INSERT INTO strategies (sid, target_file, match_regex, replace_content, description, enabled) VALUES
('2000001', '/etc/nginx/sites-available/default', 'location /admin', 'location /admin\n    allow 10.0.0.0/8;\n    deny all;', 'Restrict admin access', 1),
('2000002', '/etc/nginx/nginx.conf', 'client_max_body_size', 'client_max_body_size 1m;', 'Limit request body size', 1)
ON DUPLICATE KEY UPDATE
    target_file = VALUES(target_file),
    match_regex = VALUES(match_regex),
    replace_content = VALUES(replace_content),
    description = VALUES(description),
    enabled = VALUES(enabled);
