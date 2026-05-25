package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config describes Agent runtime configuration.
type Config struct {
	MasterAddress        string `yaml:"master_address"`
	MasterHTTPAddress    string `yaml:"master_http_address"`
	SuricataLogPath      string `yaml:"suricata_log_path"`
	SuricataReadExisting bool   `yaml:"suricata_read_existing"`
	SuricataRulePath     string `yaml:"suricata_rule_path"`
	SuricataReloadCmd    string `yaml:"suricata_reload_command"`
	SuricataTestCmd      string `yaml:"suricata_test_command"`
	MonitorIP            string `yaml:"monitor_ip"`
	AgentName            string `yaml:"agent_name"`
	ReconnectInterval    int    `yaml:"reconnect_interval"`
	HeartbeatInterval    int    `yaml:"heartbeat_interval"`
	ServiceScanInterval  int    `yaml:"service_scan_interval"`
}

type yamlConfig struct {
	Agent Config `yaml:"agent"`
}

func LoadConfig(path string) (*Config, error) {
	cfg := &Config{
		MasterAddress:       "127.0.0.1:50051",
		SuricataLogPath:     "./suricata_logs/eve.json",
		SuricataRulePath:    "./suricata_logs/dasrs_ai.rules",
		ReconnectInterval:   5,
		HeartbeatInterval:   30,
		ServiceScanInterval: 300,
	}

	data, err := os.ReadFile(path)
	if err == nil {
		var yCfg yamlConfig
		if err := yaml.Unmarshal(data, &yCfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
		if yCfg.Agent.MasterAddress != "" {
			cfg.MasterAddress = yCfg.Agent.MasterAddress
		}
		if yCfg.Agent.MasterHTTPAddress != "" {
			cfg.MasterHTTPAddress = yCfg.Agent.MasterHTTPAddress
		}
		if yCfg.Agent.SuricataLogPath != "" {
			cfg.SuricataLogPath = yCfg.Agent.SuricataLogPath
		}
		cfg.SuricataReadExisting = yCfg.Agent.SuricataReadExisting
		if yCfg.Agent.SuricataRulePath != "" {
			cfg.SuricataRulePath = yCfg.Agent.SuricataRulePath
		}
		if yCfg.Agent.SuricataReloadCmd != "" {
			cfg.SuricataReloadCmd = yCfg.Agent.SuricataReloadCmd
		}
		if yCfg.Agent.SuricataTestCmd != "" {
			cfg.SuricataTestCmd = yCfg.Agent.SuricataTestCmd
		}
		if yCfg.Agent.MonitorIP != "" {
			cfg.MonitorIP = yCfg.Agent.MonitorIP
		}
		if yCfg.Agent.AgentName != "" {
			cfg.AgentName = yCfg.Agent.AgentName
		}
		if yCfg.Agent.ReconnectInterval > 0 {
			cfg.ReconnectInterval = yCfg.Agent.ReconnectInterval
		}
		if yCfg.Agent.HeartbeatInterval > 0 {
			cfg.HeartbeatInterval = yCfg.Agent.HeartbeatInterval
		}
		if yCfg.Agent.ServiceScanInterval > 0 {
			cfg.ServiceScanInterval = yCfg.Agent.ServiceScanInterval
		}
	}

	if v := os.Getenv("MASTER_ADDRESS"); v != "" {
		cfg.MasterAddress = v
	}
	if v := os.Getenv("MASTER_HTTP_ADDRESS"); v != "" {
		cfg.MasterHTTPAddress = v
	}
	if v := os.Getenv("SURICATA_LOG_PATH"); v != "" {
		cfg.SuricataLogPath = v
	}
	if v := os.Getenv("SURICATA_READ_EXISTING"); v != "" {
		if enabled, err := strconv.ParseBool(v); err == nil {
			cfg.SuricataReadExisting = enabled
		}
	}
	if v := os.Getenv("SURICATA_RULE_PATH"); v != "" {
		cfg.SuricataRulePath = v
	}
	if v := os.Getenv("SURICATA_RELOAD_COMMAND"); v != "" {
		cfg.SuricataReloadCmd = v
	}
	if v := os.Getenv("SURICATA_TEST_COMMAND"); v != "" {
		cfg.SuricataTestCmd = v
	}
	if v := os.Getenv("MONITOR_IP"); v != "" {
		cfg.MonitorIP = v
	}
	if v := os.Getenv("AGENT_NAME"); v != "" {
		cfg.AgentName = v
	}
	if v := os.Getenv("RECONNECT_INTERVAL"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.ReconnectInterval)
	}
	if v := os.Getenv("HEARTBEAT_INTERVAL"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.HeartbeatInterval)
	}
	if v := os.Getenv("SERVICE_SCAN_INTERVAL"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.ServiceScanInterval)
	}

	if cfg.MasterHTTPAddress == "" {
		cfg.MasterHTTPAddress = deriveHTTPAddress(cfg.MasterAddress)
	}
	if cfg.AgentName == "" {
		cfg.AgentName = "agent-default"
	}

	return cfg, nil
}

func deriveHTTPAddress(masterAddress string) string {
	host := masterAddress
	if idx := strings.LastIndex(masterAddress, ":"); idx > -1 {
		host = masterAddress[:idx]
	}
	return fmt.Sprintf("%s:%d", host, 8080)
}
