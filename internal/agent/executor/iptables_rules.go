package executor

import (
	"bufio"
	"net"
	"sort"
	"strings"
)

// parseBlockedSources extracts host-level INPUT DROP sources from iptables -S output.
func parseBlockedSources(output string) []string {
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 || fields[0] != "-A" || fields[1] != "INPUT" {
			continue
		}

		source := ""
		drop := false
		for i := 2; i+1 < len(fields); i++ {
			switch fields[i] {
			case "-s", "--source":
				source = fields[i+1]
			case "-j", "--jump":
				drop = strings.EqualFold(fields[i+1], "DROP")
			}
		}
		if !drop || source == "" {
			continue
		}

		ip := singleHostIP(source)
		if ip != "" {
			seen[ip] = struct{}{}
		}
	}

	ips := make([]string, 0, len(seen))
	for ip := range seen {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	return ips
}

func singleHostIP(value string) string {
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}

	ip, network, err := net.ParseCIDR(value)
	if err != nil || ip == nil {
		return ""
	}
	ones, bits := network.Mask.Size()
	if ones != bits {
		return ""
	}
	return ip.String()
}
