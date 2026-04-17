package executor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// SuricataRuleDeployer writes AI-generated rules and optionally reloads Suricata.
type SuricataRuleDeployer struct {
	defaultRulePath string
	reloadCommand   string
}

func NewSuricataRuleDeployer(defaultRulePath, reloadCommand string) *SuricataRuleDeployer {
	return &SuricataRuleDeployer{
		defaultRulePath: strings.TrimSpace(defaultRulePath),
		reloadCommand:   strings.TrimSpace(reloadCommand),
	}
}

func (d *SuricataRuleDeployer) DeployRule(rulePath, ruleContent string) error {
	path := strings.TrimSpace(rulePath)
	if path == "" {
		path = d.defaultRulePath
	}
	if path == "" {
		return fmt.Errorf("suricata rule path is empty")
	}

	content := strings.TrimSpace(ruleContent)
	if content == "" {
		return fmt.Errorf("suricata rule content is empty")
	}
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create rule directory: %w", err)
	}

	backupPath := path + ".bak"
	_, hadExisting := fileExists(path)
	if hadExisting {
		if err := copyFile(path, backupPath); err != nil {
			return fmt.Errorf("backup existing rule file: %w", err)
		}
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("write suricata rule file: %w", err)
	}

	if err := d.reload(); err != nil {
		if hadExisting {
			_ = copyFile(backupPath, path)
		} else {
			_ = os.Remove(path)
		}
		return fmt.Errorf("reload suricata: %w", err)
	}

	return nil
}

func (d *SuricataRuleDeployer) reload() error {
	if strings.TrimSpace(d.reloadCommand) == "" {
		return nil
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/C", d.reloadCommand)
	default:
		cmd = exec.Command("/bin/sh", "-lc", d.reloadCommand)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v, output: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func fileExists(path string) (os.FileInfo, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, false
	}
	return info, true
}
