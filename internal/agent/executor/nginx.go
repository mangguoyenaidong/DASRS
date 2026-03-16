package executor

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync/atomic"
	"time"
)

// NginxPatcher Nginx 配置热修复器
type NginxPatcher struct {
	patchCount int64
}

// NewNginxPatcher 创建修复器
func NewNginxPatcher() *NginxPatcher {
	return &NginxPatcher{}
}

// SafePatch 安全修复配置
func (p *NginxPatcher) SafePatch(filePath, matchRegex, replaceContent string) error {
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

	// 5. 语法验证 (关键步骤)
	if err := p.verifyNginxConfig(filePath); err != nil {
		p.rollback(backupPath, filePath)
		return fmt.Errorf("syntax check failed, rolled back: %w", err)
	}

	// 6. 应用变更
	if err := p.reloadNginx(); err != nil {
		return fmt.Errorf("reload failed: %w", err)
	}

	atomic.AddInt64(&p.patchCount, 1)
	return nil
}

// verifyNginxConfig 验证 Nginx 配置语法
func (p *NginxPatcher) verifyNginxConfig(configPath string) error {
	cmd := exec.Command("nginx", "-t", "-c", configPath)
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

// reloadNginx 重载 Nginx
func (p *NginxPatcher) reloadNginx() error {
	cmd := exec.Command("systemctl", "reload", "nginx")
	if err := cmd.Run(); err != nil {
		// 尝试使用 service 命令
		cmd = exec.Command("service", "nginx", "reload")
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	return nil
}

// rollback 回滚
func (p *NginxPatcher) rollback(backupPath, targetPath string) {
	copyFile(backupPath, targetPath)
}

// copyFile 复制文件
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

	_, err = io.Copy(dstFile, srcFile)
	return err
}

// GetConfigPath 获取配置文件路径
func (p *NginxPatcher) GetConfigPath(siteName string) string {
	return filepath.Join("/etc/nginx/sites-available", siteName)
}

// GetPatchCount 获取修复次数
func (p *NginxPatcher) GetPatchCount() int64 {
	return atomic.LoadInt64(&p.patchCount)
}
