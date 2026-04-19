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

func TestSuricataRuleBuilderReportsEmptyMatchersClearly(t *testing.T) {
	builder := NewSuricataRuleBuilder()

	_, err := builder.Build(&ai.RuleGenResult{
		Protocol:  "http",
		Direction: "to_server",
		Message:   "test rule",
		Classtype: "web-application-attack",
	}, 9000003)
	if err == nil {
		t.Fatal("expected Build to fail for empty matchers")
	}

	if !strings.Contains(err.Error(), "empty matchers array") {
		t.Fatalf("expected detailed empty matcher error, got %v", err)
	}
}

func TestSuricataRuleBuilderReportsUnsupportedMatcherTypesClearly(t *testing.T) {
	builder := NewSuricataRuleBuilder()

	_, err := builder.Build(&ai.RuleGenResult{
		Protocol:  "http",
		Direction: "to_server",
		Message:   "test rule",
		Classtype: "web-application-attack",
		Matchers: []ai.RuleMatcher{
			{Type: "uri", Value: "/login"},
			{Type: "method", Value: "POST"},
			{Type: "content", Value: ""},
		},
	}, 9000004)
	if err == nil {
		t.Fatal("expected Build to fail for unsupported matchers")
	}

	message := err.Error()
	if !strings.Contains(message, "unsupported matcher type(s): method, uri") {
		t.Fatalf("expected unsupported type details, got %v", err)
	}
	if !strings.Contains(message, "1 matcher(s) had empty values") {
		t.Fatalf("expected empty matcher detail, got %v", err)
	}
}
