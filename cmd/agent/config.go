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
	MonitorIP         string `yaml:"monitor_ip"`        // 新增：仅监控发往此 IP 的流量
	ReconnectInterval int    `yaml:"reconnect_interval"`
	HeartbeatInterval int    `yaml:"heartbeat_interval"`
}

// yamlConfig 用于解析嵌套的 YAML 结构
type yamlConfig struct {
	Agent Config `yaml:"agent"`
}

func LoadConfig(path string) (*Config, error) {
	cfg := &Config{
		MasterAddress:     "127.0.0.1:50051", // 默认指向本地
		SuricataLogPath:   "./suricata_logs/eve.json",
		ReconnectInterval: 5,
		HeartbeatInterval: 30,
	}

	// 尝试读取配置文件（如果存在）
	data, err := os.ReadFile(path)
	if err == nil {
		var yCfg yamlConfig
		if err := yaml.Unmarshal(data, &yCfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
		// 如果配置文件中有值，则覆盖默认值
		if yCfg.Agent.MasterAddress != "" {
			cfg.MasterAddress = yCfg.Agent.MasterAddress
		}
		if yCfg.Agent.SuricataLogPath != "" {
			cfg.SuricataLogPath = yCfg.Agent.SuricataLogPath
		}
		if yCfg.Agent.MonitorIP != "" {
			cfg.MonitorIP = yCfg.Agent.MonitorIP
		}
		if yCfg.Agent.ReconnectInterval > 0 {
			cfg.ReconnectInterval = yCfg.Agent.ReconnectInterval
		}
		if yCfg.Agent.HeartbeatInterval > 0 {
			cfg.HeartbeatInterval = yCfg.Agent.HeartbeatInterval
		}
	}

	// 环境变量覆盖
	if v := os.Getenv("MASTER_ADDRESS"); v != "" {
		cfg.MasterAddress = v
	}
	if v := os.Getenv("SURICATA_LOG_PATH"); v != "" {
		cfg.SuricataLogPath = v
	}
	if v := os.Getenv("MONITOR_IP"); v != "" {
		cfg.MonitorIP = v
	}
	if v := os.Getenv("RECONNECT_INTERVAL"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.ReconnectInterval)
	}
	if v := os.Getenv("HEARTBEAT_INTERVAL"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.HeartbeatInterval)
	}

	return cfg, nil
}
