package executor

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

// MiddlewareManager 定义中间件的管理接口
type MiddlewareManager interface {
	VerifyConfig(configPath string) error
	ReloadService() error
}

// ConfigPatcher 通用的配置热修复器
type ConfigPatcher struct {
	patchCount int64
	managers   map[string]MiddlewareManager
}

// NewConfigPatcher 创建修复器并注册支持的中间件
func NewConfigPatcher() *ConfigPatcher {
	p := &ConfigPatcher{
		managers: make(map[string]MiddlewareManager),
	}

	// 默认注册 Nginx 和 Apache 的支持
	p.RegisterManager("nginx", &NginxManager{})
	p.RegisterManager("apache", &ApacheManager{})

	return p
}

// RegisterManager 注册新的中间件管理器
func (p *ConfigPatcher) RegisterManager(name string, manager MiddlewareManager) {
	p.managers[name] = manager
}

// getManager 根据路径智能推断中间件类型
func (p *ConfigPatcher) getManager(filePath string) (MiddlewareManager, error) {
	path := strings.ToLower(filePath)
	if strings.Contains(path, "nginx") {
		return p.managers["nginx"], nil
	}
	if strings.Contains(path, "apache2") || strings.Contains(path, "httpd") {
		return p.managers["apache"], nil
	}

	return nil, fmt.Errorf("could not determine middleware type for config path: %s", filePath)
}

// SafePatch 安全修复配置的核心逻辑
func (p *ConfigPatcher) SafePatch(filePath, matchRegex, replaceContent string) error {
	manager, err := p.getManager(filePath)
	if err != nil {
		return err
	}

	// 1. 创建备份
	backupPath := fmt.Sprintf("%s.bak.%d", filePath, time.Now().Unix())
	if err := copyFile(filePath, backupPath); err != nil {
		return fmt.Errorf("backup failed: %w", err)
	}

	// 2. 读取文件
	content, err := os.ReadFile(filePath)
	if err != nil {
		p.rollback(backupPath, filePath)
		return fmt.Errorf("failed to read file: %w", err)
	}

	// 3. 正则替换
	re, err := regexp.Compile(matchRegex)
	if err != nil {
		p.rollback(backupPath, filePath)
		return fmt.Errorf("invalid regex: %w", err)
	}

	newContent := re.ReplaceAllString(string(content), replaceContent)

	// 4. 写回文件
	if err := os.WriteFile(filePath, []byte(newContent), 0644); err != nil {
		p.rollback(backupPath, filePath)
		return fmt.Errorf("failed to write file: %w", err)
	}

	// 5. 语法验证 (原子性关键步骤)
	if err := manager.VerifyConfig(filePath); err != nil {
		p.rollback(backupPath, filePath) // 失败回滚
		return fmt.Errorf("syntax check failed, rolled back: %w", err)
	}

	// 6. 应用变更重载服务
	if err := manager.ReloadService(); err != nil {
		// 注意: 重载失败也应该回滚并尝试恢复原本的服务状态
		p.rollback(backupPath, filePath)
		manager.ReloadService() // 尝试用旧配置再次 reload 恢复状态
		return fmt.Errorf("reload failed, rolled back: %w", err)
	}

	atomic.AddInt64(&p.patchCount, 1)
	return nil
}

// rollback 恢复备份
func (p *ConfigPatcher) rollback(backupPath, targetPath string) {
	if err := copyFile(backupPath, targetPath); err != nil {
		fmt.Printf("CRITICAL: Rollback failed from %s to %s: %v\n", backupPath, targetPath, err)
	}
}

// GetPatchCount 获取修复次数
func (p *ConfigPatcher) GetPatchCount() int64 {
	return atomic.LoadInt64(&p.patchCount)
}

// copyFile 辅助函数：复制文件
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err = io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	return dstFile.Sync()
}

// --- Nginx Manager 实现 ---

type NginxManager struct{}

func (m *NginxManager) VerifyConfig(configPath string) error {
	cmd := exec.Command("nginx", "-t", "-c", configPath)
	return cmd.Run()
}

func (m *NginxManager) ReloadService() error {
	cmd := exec.Command("systemctl", "reload", "nginx")
	if err := cmd.Run(); err != nil {
		// 备用命令
		cmd = exec.Command("service", "nginx", "reload")
		return cmd.Run()
	}
	return nil
}

// --- Apache Manager 实现 ---

type ApacheManager struct{}

func (m *ApacheManager) VerifyConfig(configPath string) error {
	// apache2ctl configtest 会检查默认的主配置和包含的所有子配置
	// 为了仅检查特定的配置，这里依赖整体的 apache2ctl -t
	// 实际生产中可以通过指定 -f 来检查独立的 conf，但通常 httpd 检查整体状态即可
	cmd := exec.Command("apache2ctl", "configtest")
	if err := cmd.Run(); err != nil {
		// 尝试 CentOS/RHEL 下的 httpd 命令
		cmd = exec.Command("httpd", "-t")
		return cmd.Run()
	}
	return nil
}

func (m *ApacheManager) ReloadService() error {
	cmd := exec.Command("systemctl", "reload", "apache2")
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("systemctl", "reload", "httpd")
		return cmd.Run()
	}
	return nil
}
