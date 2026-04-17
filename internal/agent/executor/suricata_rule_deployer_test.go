package executor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSuricataRuleDeployerWritesRuleFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "suricata-rule")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	rulePath := filepath.Join(tmpDir, "dasrs_ai.rules")
	deployer := NewSuricataRuleDeployer(rulePath, "")

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
