package model

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config Master 配置结构
type Config struct {
	SourcePath string `yaml:"-"`
	Master     struct {
		Host     string `yaml:"host"`
		GRPCPort int    `yaml:"grpc_port"`
		HTTPPort int    `yaml:"http_port"`
		Database struct {
			Host         string `yaml:"host"`
			Port         int    `yaml:"port"`
			Username     string `yaml:"username"`
			Password     string `yaml:"password"`
			Name         string `yaml:"name"`
			MaxOpenConns int    `yaml:"max_open_conns"`
			MaxIdleConns int    `yaml:"max_idle_conns"`
		} `yaml:"database"`
		Redis struct {
			Host     string `yaml:"host"`
			Port     int    `yaml:"port"`
			Password string `yaml:"password"`
			DB       int    `yaml:"db"`
			PoolSize int    `yaml:"pool_size"`
		} `yaml:"redis"`
		Intelligence struct {
			RepairThreshold     int      `yaml:"repair_threshold"`
			BlockThreshold      int      `yaml:"block_threshold"`
			TimeWindow          int      `yaml:"time_window"`
			MaxAlertsPerWindow  int      `yaml:"max_alerts_per_window"`
			Whitelist           []string `yaml:"whitelist"`
			DemoMode            bool     `yaml:"demo_mode"`
			DemoBlockThreshold  int      `yaml:"demo_block_threshold"`
			DemoRepairThreshold int      `yaml:"demo_repair_threshold"`
			DemoExploitBonus    int      `yaml:"demo_exploit_bonus"`
		} `yaml:"intelligence"`
		AI struct {
			Enabled  bool   `yaml:"enabled"`
			Provider string `yaml:"provider"`
			API      struct {
				Vendor         string `yaml:"vendor"`
				BaseURL        string `yaml:"base_url"`
				APIKey         string `yaml:"api_key"`
				Model          string `yaml:"model"`
				TimeoutSeconds int    `yaml:"timeout_seconds"`
			} `yaml:"api"`
			Prompts struct {
				RuleGenerationSystem string `yaml:"rule_generation_system"`
				RuleGenerationUser   string `yaml:"rule_generation_user"`
				AlertAnalysisSystem  string `yaml:"alert_analysis_system"`
				AlertAnalysisUser    string `yaml:"alert_analysis_user"`
			} `yaml:"prompts"`
			Testing struct {
				CommandTemplate string `yaml:"command_template"`
				SuccessMatch    string `yaml:"success_match"`
			} `yaml:"testing"`
		} `yaml:"ai"`
	} `yaml:"master"`
	Agent struct {
		MasterAddress     string `yaml:"master_address"`
		SuricataLogPath   string `yaml:"suricata_log_path"`
		ReconnectInterval int    `yaml:"reconnect_interval"`
		HeartbeatInterval int    `yaml:"heartbeat_interval"`
	} `yaml:"agent"`
	Logging struct {
		Level  string `yaml:"level"`
		Format string `yaml:"format"`
	} `yaml:"logging"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	cfg.SourcePath = path

	return &cfg, nil
}

func SaveConfig(path string, cfg *Config) error {
	if cfg == nil {
		return os.ErrInvalid
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
