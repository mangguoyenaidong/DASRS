package service

import (
	"fmt"
	"regexp"
	"strings"

	"security-response-system/internal/master/ai"
)

// SuricataRuleBuilder converts structured AI output into candidate rule text.
type SuricataRuleBuilder struct{}

func NewSuricataRuleBuilder() *SuricataRuleBuilder {
	return &SuricataRuleBuilder{}
}

func (b *SuricataRuleBuilder) Build(result *ai.RuleGenResult, sid uint) (string, error) {
	if result == nil {
		return "", fmt.Errorf("rule generation result is nil")
	}

	protocol := strings.ToLower(strings.TrimSpace(result.Protocol))
	if protocol == "" {
		protocol = "http"
	}
	if !isSupportedProtocol(protocol) {
		return "", fmt.Errorf("unsupported protocol %q", protocol)
	}

	destPort := "$HTTP_PORTS"
	if len(result.TargetPorts) > 0 {
		ports := sanitizePorts(result.TargetPorts)
		if len(ports) > 0 {
			if len(ports) == 1 {
				destPort = ports[0]
			} else {
				destPort = "[" + strings.Join(ports, ",") + "]"
			}
		}
	}

	flow := "to_server,established"
	switch strings.ToLower(strings.TrimSpace(result.Direction)) {
	case "to_client":
		flow = "to_client,established"
	case "either":
		flow = "established"
	}

	message := sanitizeOptionValue(result.Message)
	if message == "" {
		message = sanitizeOptionValue(result.AttackType)
	}
	if message == "" {
		message = "DASRS AI generated candidate rule"
	}

	classtype := sanitizeToken(result.Classtype)
	if classtype == "" {
		classtype = "attempted-admin"
	}

	var options []string
	options = append(options, fmt.Sprintf(`msg:"%s"`, message))
	options = append(options, fmt.Sprintf("flow:%s", flow))

	matcherCount := 0
	for _, matcher := range result.Matchers {
		mType := strings.ToLower(strings.TrimSpace(matcher.Type))
		value := strings.TrimSpace(matcher.Value)
		if value == "" {
			continue
		}
		switch mType {
		case "content":
			options = append(options, fmt.Sprintf(`content:"%s"`, escapeContent(value)))
			matcherCount++
		case "pcre":
			pcre := escapePCRE(value)
			if pcre != "" {
				options = append(options, fmt.Sprintf(`pcre:"%s"`, pcre))
				matcherCount++
			}
		}
	}
	if matcherCount == 0 {
		return "", fmt.Errorf("no valid matchers generated for candidate rule")
	}

	options = append(options, fmt.Sprintf("classtype:%s", classtype))
	options = append(options, fmt.Sprintf("sid:%d", sid))
	options = append(options, "rev:1")

	return fmt.Sprintf(
		"alert %s any any -> $HOME_NET %s (%s;)",
		protocol,
		destPort,
		strings.Join(options, "; "),
	), nil
}

func isSupportedProtocol(protocol string) bool {
	switch protocol {
	case "http", "tcp", "udp", "dns", "tls":
		return true
	default:
		return false
	}
}

func sanitizeOptionValue(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, `"`, `'`)
	return value
}

func sanitizeToken(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-':
			return r
		default:
			return -1
		}
	}, value)
}

func escapeContent(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, ";", `\;`)
	return replacer.Replace(value)
}

func escapePCRE(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	if strings.HasPrefix(value, "/") {
		lastSlash := strings.LastIndex(value, "/")
		if lastSlash > 0 {
			body := value[1:lastSlash]
			flags := value[lastSlash+1:]
			body = strings.ReplaceAll(body, `"`, `\"`)
			flags = sanitizePCREFlags(flags)
			if flags != "" {
				return "/" + body + "/" + flags
			}
			return "/" + body + "/"
		}
	}

	value = strings.ReplaceAll(value, `"`, `\"`)
	return "/" + value + "/"
}

func nextCandidateSID(id uint) uint {
	return 9_000_000 + id
}

func sanitizePorts(ports []string) []string {
	valid := make([]string, 0, len(ports))
	pattern := regexp.MustCompile(`^(\$?[A-Za-z0-9_\-]+|\d{1,5}(:\d{1,5})?)$`)
	for _, port := range ports {
		port = strings.TrimSpace(port)
		if port == "" {
			continue
		}
		if pattern.MatchString(port) {
			valid = append(valid, port)
		}
	}
	return valid
}

func sanitizePCREFlags(flags string) string {
	if flags == "" {
		return ""
	}

	var builder strings.Builder
	seen := map[rune]struct{}{}
	for _, flag := range flags {
		switch flag {
		case 'i', 'm', 's', 'x', 'A', 'E', 'G', 'R', 'U', 'I', 'P', 'H', 'D', 'M', 'C', 'K', 'S', 'Y', 'B', 'O':
			if _, ok := seen[flag]; ok {
				continue
			}
			seen[flag] = struct{}{}
			builder.WriteRune(flag)
		}
	}
	return builder.String()
}
