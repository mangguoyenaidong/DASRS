//go:build !linux && !windows
// +build !linux,!windows

package executor

import (
	"fmt"
	"sync/atomic"
)

// IPBlocker 在非 Linux 平台上的替代实现，用于本地编译和测试。
type IPBlocker struct {
	blockCount int64
}

// NewIPBlocker 创建一个 IPBlocker 实例（非 Linux 平台）
func NewIPBlocker() *IPBlocker {
	return &IPBlocker{}
}

// GetBlockCount 返回封禁计数
func (b *IPBlocker) GetBlockCount() int64 {
	return atomic.LoadInt64(&b.blockCount)
}

// BlockIP 在非 Linux 平台上不执行实际封禁，仅记录操作并返回错误
func (b *IPBlocker) BlockIP(ip string) error {
	return fmt.Errorf("ip blocking is not supported on this platform: %s", ip)
}

// UnblockIP 在非 Linux 平台上不执行实际解封，仅记录操作并返回错误
func (b *IPBlocker) UnblockIP(ip string) error {
	return fmt.Errorf("ip unblocking is not supported on this platform: %s", ip)
}

// ListBlockedIPs is unavailable on platforms without iptables support.
func (b *IPBlocker) ListBlockedIPs() ([]string, error) {
	return nil, fmt.Errorf("iptables block synchronization is not supported on this platform")
}
