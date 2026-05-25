//go:build windows
// +build windows

package executor

import (
	"fmt"
	"log"
	"os/exec"
	"sync/atomic"
)

// IPBlocker Windows 平台的防火墙阻断器
type IPBlocker struct {
	blockCount int64
}

func NewIPBlocker() *IPBlocker {
	return &IPBlocker{}
}

// GetBlockCount 获取封禁次数
func (b *IPBlocker) GetBlockCount() int64 {
	return atomic.LoadInt64(&b.blockCount)
}

// BlockIP 封禁 IP (Windows: netsh)
func (b *IPBlocker) BlockIP(ip string) error {
	log.Printf("[Windows] Blocking IP: %s", ip)

	ruleName := fmt.Sprintf("DASRS_BLOCK_%s", ip)

	// netsh advfirewall firewall add rule name="DASRS_BLOCK_IP" dir=in action=block remoteip=<ip>
	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		fmt.Sprintf("name=%s", ruleName), "dir=in", "action=block", fmt.Sprintf("remoteip=%s", ip))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to block IP %s via netsh: %v, output: %s", ip, err, string(output))
	}

	atomic.AddInt64(&b.blockCount, 1)
	return nil
}

// UnblockIP 解封 IP (Windows: netsh)
func (b *IPBlocker) UnblockIP(ip string) error {
	log.Printf("[Windows] Unblocking IP: %s", ip)

	ruleName := fmt.Sprintf("DASRS_BLOCK_%s", ip)

	// netsh advfirewall firewall delete rule name="DASRS_BLOCK_IP"
	cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", fmt.Sprintf("name=%s", ruleName))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to unblock IP %s via netsh: %v, output: %s", ip, err, string(output))
	}

	return nil
}

// ListBlockedIPs is unavailable because this synchronization targets iptables agents.
func (b *IPBlocker) ListBlockedIPs() ([]string, error) {
	return nil, fmt.Errorf("iptables block synchronization is only supported on Linux agents")
}
