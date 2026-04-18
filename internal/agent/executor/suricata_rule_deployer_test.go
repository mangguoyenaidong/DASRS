package executor

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSuricataRuleDeployerWritesRuleFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "suricata-rule")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	rulePath := filepath.Join(tmpDir, "dasrs_ai.rules")
	deployer := NewSuricataRuleDeployer(rulePath, "", "")

	err = deployer.DeployRule("", `alert http any any -> $HOME_NET any (msg:"test"; sid:9000001; rev:1;)`)
	if err != nil {
		t.Fatalf("DeployRule failed: %v", err)
	}

	data, err := os.ReadFile(rulePath)
	if err != nil {
		t.Fatal(err)
	}

	if string(data) == "" {
		t.Fatal("expected written rule content, got empty file")
	}
}

func TestSuricataRuleDeployerRestoresBackupOnReloadFailure(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "suricata-rule")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	rulePath := filepath.Join(tmpDir, "dasrs_ai.rules")
	original := `alert http any any -> $HOME_NET any (msg:"original"; sid:9000001; rev:1;)`
	if err := os.WriteFile(rulePath, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}

	deployer := NewSuricataRuleDeployer(rulePath, "exit 1", "")
	err = deployer.DeployRule("", `alert http any any -> $HOME_NET any (msg:"replacement"; sid:9000002; rev:1;)`)
	if err == nil {
		t.Fatal("expected DeployRule to fail when reload command fails")
	}

	data, err := os.ReadFile(rulePath)
	if err != nil {
		t.Fatal(err)
	}

	if string(data) != original {
		t.Fatalf("expected original rule content to be restored, got %s", string(data))
	}
}

func TestSuricataRuleDeployerRunsTestCommand(t *testing.T) {
	command := "cat {{RULE_FILE}}"
	if runtime.GOOS == "windows" {
		command = "type {{RULE_FILE}}"
	}
	deployer := NewSuricataRuleDeployer("", "", command)

	output, err := deployer.TestRule(`alert http any any -> $HOME_NET any (msg:"test"; sid:9000003; rev:1;)`, "")
	if err != nil {
		t.Fatalf("TestRule failed: %v", err)
	}

	if output == "" {
		t.Fatal("expected test command output, got empty string")
	}
}
