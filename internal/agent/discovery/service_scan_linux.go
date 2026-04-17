//go:build linux

package discovery

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type LocalServiceScanner struct{}

func NewLocalServiceScanner() Scanner {
	return &LocalServiceScanner{}
}

func (s *LocalServiceScanner) Scan(ctx context.Context) ([]ServiceRecord, error) {
	cmd := exec.CommandContext(ctx, "ss", "-lntupH")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("scan local services with ss: %w", err)
	}

	records := make([]ServiceRecord, 0)
	seen := make(map[string]struct{})
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	timestamp := time.Now().Format(time.RFC3339)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		record, ok := parseSSLine(line, timestamp)
		if !ok {
			continue
		}

		key := fmt.Sprintf("%s|%d|%s|%s", record.Protocol, record.Port, record.Listen, record.Process)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		records = append(records, record)
	}

	return normalizeRecords(records), nil
}

var (
	processPattern = regexp.MustCompile(`users:\(\("([^"]+)"`)
	pidPattern     = regexp.MustCompile(`pid=(\d+)`)
)

func parseSSLine(line, timestamp string) (ServiceRecord, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return ServiceRecord{}, false
	}

	protocol := strings.ToLower(fields[0])
	listenField := fields[4]
	if len(fields) > 5 && strings.HasPrefix(fields[5], "users:") {
		// keep listenField as-is
	}

	listenAddr, port, ok := splitListenAddress(listenField)
	if !ok {
		return ServiceRecord{}, false
	}

	process := detectProcess(line)
	pid := detectPID(line)
	cmdline := readProcessCmdline(pid)
	name := inferServiceName(port, process, cmdline)
	if name == "" {
		name = "unknown"
	}

	return ServiceRecord{
		Name:      name,
		Port:      port,
		Protocol:  protocol,
		Process:   process,
		Listen:    listenAddr,
		Status:    "running",
		Source:    "agent-local-scan",
		UpdatedAt: timestamp,
	}, true
}

func splitListenAddress(raw string) (string, int, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", 0, false
	}

	if strings.HasPrefix(raw, "[") {
		end := strings.LastIndex(raw, "]:")
		if end == -1 {
			return "", 0, false
		}
		addr := raw[1:end]
		port, err := strconv.Atoi(raw[end+2:])
		if err != nil {
			return "", 0, false
		}
		return addr, port, true
	}

	idx := strings.LastIndex(raw, ":")
	if idx == -1 || idx == len(raw)-1 {
		return "", 0, false
	}
	port, err := strconv.Atoi(raw[idx+1:])
	if err != nil {
		return "", 0, false
	}
	return raw[:idx], port, true
}

func detectProcess(line string) string {
	matches := processPattern.FindStringSubmatch(line)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func detectPID(line string) int {
	matches := pidPattern.FindStringSubmatch(line)
	if len(matches) != 2 {
		return 0
	}
	pid, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0
	}
	return pid
}

func readProcessCmdline(pid int) string {
	if pid <= 0 {
		return ""
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(data) == 0 {
		return ""
	}
	cmdline := strings.ReplaceAll(string(data), "\x00", " ")
	return strings.TrimSpace(cmdline)
}

func inferServiceName(port int, process, cmdline string) string {
	process = strings.ToLower(process)
	cmdline = strings.ToLower(cmdline)

	if fingerprinted := inferJavaService(port, process, cmdline); fingerprinted != "" {
		return fingerprinted
	}

	switch {
	case strings.Contains(process, "nginx"):
		return "nginx"
	case strings.Contains(process, "apache"), strings.Contains(process, "httpd"):
		return "apache"
	case strings.Contains(process, "mysqld"), strings.Contains(process, "mariadbd"):
		return "mysql"
	case strings.Contains(process, "redis"):
		return "redis"
	case strings.Contains(process, "postgres"):
		return "postgresql"
	case strings.Contains(process, "sshd"):
		return "ssh"
	}

	switch port {
	case 22:
		return "ssh"
	case 80, 8080, 8000, 8008:
		return "http"
	case 443, 8443:
		return "https"
	case 3306:
		return "mysql"
	case 5432:
		return "postgresql"
	case 6379:
		return "redis"
	case 9200:
		return "elasticsearch"
	default:
		return process
	}
}

func inferJavaService(port int, process, cmdline string) string {
	if !strings.Contains(process, "java") && !strings.Contains(cmdline, "java") {
		return ""
	}

	switch {
	case strings.Contains(cmdline, "catalina.startup.bootstrap"),
		strings.Contains(cmdline, "catalina.home"),
		strings.Contains(cmdline, "catalina.base"),
		strings.Contains(cmdline, "tomcat"):
		return "tomcat"
	case strings.Contains(cmdline, "jenkins.war"),
		strings.Contains(cmdline, "hudson.war"):
		return "jenkins"
	case strings.Contains(cmdline, "nacos"):
		return "nacos"
	case strings.Contains(cmdline, "org.elasticsearch.bootstrap.elasticsearch"),
		strings.Contains(cmdline, "elasticsearch"):
		return "elasticsearch"
	case strings.Contains(cmdline, "kafka.kafka"),
		strings.Contains(cmdline, "kafka-server-start"):
		return "kafka"
	case strings.Contains(cmdline, "org.springframework.boot.loader"),
		strings.Contains(cmdline, "jarlauncher"),
		strings.Contains(cmdline, "propertieslauncher"):
		if port == 8080 || port == 8443 || port == 8090 {
			return "spring-boot"
		}
		return "java-service"
	default:
		return "java-service"
	}
}
