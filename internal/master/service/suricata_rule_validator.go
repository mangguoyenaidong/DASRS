package service

import (
	"fmt"
	"regexp"
	"strings"
)

// SuricataRuleValidator performs lightweight validation for AI-generated rules.
type SuricataRuleValidator struct{}

func NewSuricataRuleValidator() *SuricataRuleValidator {
	return &SuricataRuleValidator{}
}

func (v *SuricataRuleValidator) Validate(rule string) error {
	trimmed := strings.TrimSpace(rule)
	if trimmed == "" {
		return fmt.Errorf("generated rule is empty")
	}
	if !strings.HasPrefix(trimmed, "alert ") {
		return fmt.Errorf("generated rule must start with 'alert'")
	}
	if len(trimmed) > 4096 {
		return fmt.Errorf("generated rule is unexpectedly long")
	}
	required := []string{"msg:", "sid:", "rev:"}
	for _, token := range required {
		if !strings.Contains(trimmed, token) {
			return fmt.Errorf("generated rule missing required token %s", token)
		}
	}
	if !regexp.MustCompile(`^alert\s+(http|tcp|udp|dns|tls)\s+`).MatchString(trimmed) {
		return fmt.Errorf("generated rule uses unsupported protocol")
	}
	if !strings.Contains(trimmed, "content:") && !strings.Contains(trimmed, "pcre:") {
		return fmt.Errorf("generated rule must contain at least one matcher")
	}
	if strings.Contains(trimmed, "drop ") || strings.Contains(trimmed, "reject ") {
		return fmt.Errorf("generated rule must stay in detect-only mode")
	}
	if !strings.HasSuffix(trimmed, ");") {
		return fmt.Errorf("generated rule must end with ');'")
	}
	return nil
}
