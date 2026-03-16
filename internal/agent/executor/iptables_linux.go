//go:build linux
// +build linux

package executor

import (
	"fmt"
	"log"
	"os/exec"
	"sync/atomic"
)

// IPBlocker Linux 平台的 iptables 阻断器
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

// BlockIP 封禁 IP (Linux: iptables)
func (b *IPBlocker) BlockIP(ip string) error {
	log.Printf("[Linux] Blocking IP: %s", ip)

	// iptables -A INPUT -s <ip> -j DROP
	cmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to block IP %s via iptables: %v, output: %s", ip, err, string(output))
	}

	atomic.AddInt64(&b.blockCount, 1)
	return nil
}

// UnblockIP 解封 IP (Linux: iptables)
func (b *IPBlocker) UnblockIP(ip string) error {
	log.Printf("[Linux] Unblocking IP: %s", ip)

	// iptables -D INPUT -s <ip> -j DROP
	cmd := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to unblock IP %s via iptables: %v, output: %s", ip, err, string(output))
	}

	return nil
}
