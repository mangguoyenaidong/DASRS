package executor

import (
	"fmt"
	"os/exec"
	"sync/atomic"
)

// IPBlocker IP 阻断器
type IPBlocker struct {
	blockCount int64
}

// NewIPBlocker 创建阻断器
func NewIPBlocker() *IPBlocker {
	return &IPBlocker{}
}

// BlockIP 封禁 IP
func (b *IPBlocker) BlockIP(ip string) error {
	// 检查是否已经封禁
	if b.isBlocked(ip) {
		return nil
	}

	// 使用 iptables 封禁 IP
	cmd := exec.Command("iptables", "-I", "INPUT", "-s", ip, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to block IP %s: %w", ip, err)
	}

	atomic.AddInt64(&b.blockCount, 1)
	return nil
}

// UnblockIP 解封 IP
func (b *IPBlocker) UnblockIP(ip string) error {
	cmd := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to unblock IP %s: %w", ip, err)
	}

	return nil
}

// isBlocked 检查 IP 是否已被封禁
func (b *IPBlocker) isBlocked(ip string) bool {
	cmd := exec.Command("iptables", "-C", "INPUT", "-s", ip, "-j", "DROP")
	err := cmd.Run()
	return err == nil
}

// GetBlockCount 获取封禁数量
func (b *IPBlocker) GetBlockCount() int64 {
	return atomic.LoadInt64(&b.blockCount)
}
