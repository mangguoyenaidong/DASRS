package service

import (
	"strings"
	"testing"

	"security-response-system/internal/master/ai"
)

func TestSuricataRuleBuilderWrapsMultiplePorts(t *testing.T) {
	builder := NewSuricataRuleBuilder()

	rule, err := builder.Build(&ai.RuleGenResult{
		Protocol:    "http",
		Direction:   "to_server",
		Message:     "test rule",
		Classtype:   "web-application-attack",
		TargetPorts: []string{"80", "443"},
		Matchers: []ai.RuleMatcher{
			{Type: "content", Value: "/login"},
		},
	}, 9000001)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	if !strings.Contains(rule, "-> $HOME_NET [80,443] ") {
		t.Fatalf("expected multi-port list in rule, got %s", rule)
	}
}

func TestSuricataRuleBuilderPreservesPCREFlags(t *testing.T) {
	builder := NewSuricataRuleBuilder()

	rule, err := builder.Build(&ai.RuleGenResult{
		Protocol:  "http",
		Direction: "to_server",
		Message:   "test rule",
		Classtype: "web-application-attack",
		Matchers: []ai.RuleMatcher{
			{Type: "pcre", Value: `/cmd=.*(bash|sh|curl)/Ui`},
		},
	}, 9000002)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	if !strings.Contains(rule, `pcre:"/cmd=.*(bash|sh|curl)/Ui"`) {
		t.Fatalf("expected PCRE flags to be preserved, got %s", rule)
	}
}
