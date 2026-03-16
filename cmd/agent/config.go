package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config Agent 配置结构
type Config struct {
	MasterAddress     string `yaml:"master_address"`
	SuricataLogPath   string `yaml:"suricata_log_path"`
	ReconnectInterval int    `yaml:"reconnect_interval"`
	HeartbeatInterval int    `yaml:"heartbeat_interval"`
}

func LoadConfig(path string) (*Config, error) {
	cfg := &Config{
		MasterAddress:     "master:50051",
		SuricataLogPath:   "/var/log/suricata/eve.json",
		ReconnectInterval: 5,
		HeartbeatInterval: 30,
	}

	// 尝试读取配置文件（如果存在）
	data, err := os.ReadFile(path)
	if err == nil {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	// 环境变量覆盖
	if v := os.Getenv("MASTER_ADDRESS"); v != "" {
		cfg.MasterAddress = v
	}
	if v := os.Getenv("SURICATA_LOG_PATH"); v != "" {
		cfg.SuricataLogPath = v
	}
	if v := os.Getenv("RECONNECT_INTERVAL"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.ReconnectInterval)
	}
	if v := os.Getenv("HEARTBEAT_INTERVAL"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.HeartbeatInterval)
	}

	return cfg, nil
}
