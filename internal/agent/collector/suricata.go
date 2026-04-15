package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	pb "security-response-system/internal/proto"

	"github.com/hpcloud/tail"
)

// SuricataCollector Suricata 日志采集器
type SuricataCollector struct {
	filePath   string
	localIP    string
	monitorIP  string // 新增：仅上报目的 IP 为此地址的告警
	offsetFile string // 进度保存文件路径
	tail       *tail.Tail
	ctx        context.Context
	cancel     context.CancelFunc
	alertCount int64
}

// NewSuricataCollector 创建采集器
func NewSuricataCollector(filePath, localIP, monitorIP string) *SuricataCollector {
	ctx, cancel := context.WithCancel(context.Background())
	
	// 根据日志路径生成唯一的进度文件名 (处理路径中的特殊字符)
	cleanPath := strings.NewReplacer("/", "_", "\\", "_", ":", "_").Replace(filePath)
	offsetFile := fmt.Sprintf(".suricata_%s.offset", cleanPath)

	return &SuricataCollector{
		filePath:   filePath,
		localIP:    localIP,
		monitorIP:  monitorIP,
		offsetFile: offsetFile,
		ctx:        ctx,
		cancel:     cancel,
	}
}

// GetAlertCount 获取收集到的告警数量
func (c *SuricataCollector) GetAlertCount() int64 {
	return atomic.LoadInt64(&c.alertCount)
}

// Start 启动采集
func (c *SuricataCollector) Start(reportFunc func(*pb.AlertReportRequest)) error {
	var err error

	// 1. 确定起始读取位置 (Seek Location)
	seekInfo := c.calculateStartOffset()

	// 2. 启动 Tail
	c.tail, err = tail.TailFile(c.filePath, tail.Config{
		Follow:    true,
		ReOpen:    true, // 支持文件轮转
		MustExist: false,
		Poll:      true,
		Location:  seekInfo,
	})

	if err != nil {
		return fmt.Errorf("failed to tail file %s: %w", c.filePath, err)
	}

	log.Printf("Started Suricata collector on %s (Offset: %v)", c.filePath, seekInfo.Offset)

	go func() {
		// 每 5 秒同步一次进度到磁盘
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-c.ctx.Done():
				c.cleanup()
				return
			case <-ticker.C:
				c.saveOffset()
			case line, ok := <-c.tail.Lines:
				if !ok {
					log.Println("Suricata tail channel closed")
					return
				}
				if line.Err != nil {
					log.Printf("Tail error: %v", line.Err)
					continue
				}
				c.processLine(line.Text, reportFunc)
			}
		}
	}()

	return nil
}

// calculateStartOffset 确定启动时的偏移量
func (c *SuricataCollector) calculateStartOffset() *tail.SeekInfo {
	// 默认从文件开头读 (确保不漏掉上次关闭后的日志)
	defaultSeek := &tail.SeekInfo{Offset: 0, Whence: os.SEEK_SET}

	// 检查进度文件
	data, err := os.ReadFile(c.offsetFile)
	if err != nil {
		return defaultSeek
	}

	var savedOffset int64
	if _, err := fmt.Sscanf(string(data), "%d", &savedOffset); err != nil {
		return defaultSeek
	}

	// 检查当前文件大小，防止因日志轮转导致偏移量越界
	info, err := os.Stat(c.filePath)
	if err != nil {
		return defaultSeek // 文件不存在，让 tail 自己处理
	}

	if savedOffset > info.Size() {
		log.Printf("Warning: Saved offset %d is greater than file size %d. Log might be rotated. Resetting to 0.", savedOffset, info.Size())
		return defaultSeek
	}

	return &tail.SeekInfo{Offset: savedOffset, Whence: os.SEEK_SET}
}

// saveOffset 保存当前读取位置
func (c *SuricataCollector) saveOffset() {
	if c.tail == nil {
		return
	}
	// Tell() 返回的是底层文件指针的位置
	// 注意：由于 tail 库有缓冲区，Tell() 可能比已处理的 Line 稍微领先一点
	offset, err := c.tail.Tell()
	if err != nil {
		return
	}
	_ = os.WriteFile(c.offsetFile, []byte(fmt.Sprintf("%d", offset)), 0644)
}

// Stop 停止采集
func (c *SuricataCollector) Stop() {
	c.cancel()
}

// cleanup 内部清理逻辑
func (c *SuricataCollector) cleanup() {
	log.Println("Stopping Suricata collector and saving final offset...")
	c.saveOffset()
	if c.tail != nil {
		c.tail.Stop()
		c.tail.Cleanup()
	}
}

// processLine 解析单行 JSON 日志
func (c *SuricataCollector) processLine(line string, reportFunc func(*pb.AlertReportRequest)) {
	var eve struct {
		Timestamp string `json:"timestamp"`
		EventType string `json:"event_type"`
		SrcIP     string `json:"src_ip"`
		DestIP    string `json:"dest_ip"`
		Alert     struct {
			SignatureID int    `json:"signature_id"`
			Signature   string `json:"signature"`
			Severity    int    `json:"severity"`
		} `json:"alert"`
		Payload string `json:"payload"`
	}

	if err := json.Unmarshal([]byte(line), &eve); err != nil {
		return
	}

	if eve.EventType != "alert" {
		return
	}

	// 过滤本机流量
	if c.localIP != "" && c.localIP != "0.0.0.0" {
		if eve.SrcIP != c.localIP && eve.DestIP != c.localIP {
			return
		}
	}

	// 过滤特定监控目标 IP (如果配置了)
	if c.monitorIP != "" {
		if eve.DestIP != c.monitorIP {
			return
		}
	}

	// 时间解析
	t, err := time.Parse(time.RFC3339Nano, eve.Timestamp)
	var ts int64
	if err != nil {
		// 备选格式处理
		t, _ = time.Parse("2006-01-02T15:04:05.999999-0700", eve.Timestamp)
		ts = t.UnixMilli()
	} else {
		ts = t.UnixMilli()
	}

	severity := "low"
	switch eve.Alert.Severity {
	case 1: severity = "high"
	case 2: severity = "medium"
	case 3: severity = "low"
	}

	req := &pb.AlertReportRequest{
		Sid:           fmt.Sprintf("%d", eve.Alert.SignatureID),
		Payload:       eve.Payload,
		SourceIp:      eve.SrcIP,
		DestIp:        eve.DestIP,
		Timestamp:     ts,
		Severity:      severity,
		SignatureName: eve.Alert.Signature,
	}

	atomic.AddInt64(&c.alertCount, 1)
	reportFunc(req)
}
