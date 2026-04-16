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

	// 1. 幂等性检查：先检查规则是否已经存在 (iptables -C)
	checkCmd := exec.Command("iptables", "-C", "INPUT", "-s", ip, "-j", "DROP")
	if err := checkCmd.Run(); err == nil {
		log.Printf("[Linux] IP %s is already blocked, skipping rule addition", ip)
		return nil // 规则已存在，直接返回成功
	}

	// 2. 只有不存在时才执行添加 (iptables -I 优先置顶，更安全)
	cmd := exec.Command("iptables", "-I", "INPUT", "-s", ip, "-j", "DROP")
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

	// 1. 检查规则是否存在，存在才删除
	checkCmd := exec.Command("iptables", "-C", "INPUT", "-s", ip, "-j", "DROP")
	if err := checkCmd.Run(); err != nil {
		log.Printf("[Linux] IP %s is not in block list, nothing to unblock", ip)
		return nil // 规则本身就不存在，无需删除
	}

	// 2. 执行删除操作
	cmd := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to unblock IP %s via iptables: %v, output: %s", ip, err, string(output))
	}

	return nil
}
