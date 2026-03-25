package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync/atomic"
	"time"

	pb "security-response-system/internal/proto"

	"github.com/hpcloud/tail"
)

// SuricataCollector Suricata 日志采集器
type SuricataCollector struct {
	filePath   string
	tail       *tail.Tail
	ctx        context.Context
	cancel     context.CancelFunc
	alertCount int64
}

// NewSuricataCollector 创建采集器
func NewSuricataCollector(filePath string) *SuricataCollector {
	ctx, cancel := context.WithCancel(context.Background())
	return &SuricataCollector{
		filePath: filePath,
		ctx:      ctx,
		cancel:   cancel,
	}
}

// GetAlertCount 获取收集到的告警数量
func (c *SuricataCollector) GetAlertCount() int64 {
	return atomic.LoadInt64(&c.alertCount)
}

// Start 启动采集，使用回调函数处理上报逻辑
func (c *SuricataCollector) Start(reportFunc func(*pb.AlertReportRequest)) error {
	var err error

	// 使用 tail 库监控日志文件
	c.tail, err = tail.TailFile(c.filePath, tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: false,
		Poll:      true,
		Location:  &tail.SeekInfo{Offset: 0, Whence: os.SEEK_END}, // 从文件末尾开始读取
		Location:  &tail.SeekInfo{Offset: 0, Whence: os.SEEK_SET}, // 从文件开头读取，以便获取历史告警记录
	})

	if err != nil {
		return fmt.Errorf("failed to tail file %s: %w", c.filePath, err)
	}

	log.Printf("Started collecting Suricata logs from %s", c.filePath)

	go func() {
		for {
			select {
			case <-c.ctx.Done():
				c.tail.Cleanup()
				return
			case line, ok := <-c.tail.Lines:
				if !ok {
					log.Println("Tail channel closed")
					return
				}
				c.processLine(line.Text, reportFunc)
			}
		}
	}()

	return nil
}

// Stop 停止采集
func (c *SuricataCollector) Stop() {
	c.cancel()
	if c.tail != nil {
		c.tail.Stop()
		c.tail.Cleanup()
	}
	log.Println("Suricata log collector stopped")
}

// processLine 解析单行 JSON 日志
func (c *SuricataCollector) processLine(line string, reportFunc func(*pb.AlertReportRequest)) {
	// 仅解析需要的字段，提高性能
	var eve struct {
		Timestamp string `json:"timestamp"`
		EventType string `json:"event_type"`
		SrcIP     string `json:"src_ip"`
		Alert     struct {
			SignatureID int    `json:"signature_id"`
			Signature   string `json:"signature"`
			Severity    int    `json:"severity"`
		} `json:"alert"`
		Payload string `json:"payload"` // Base64 编码的 payload (如果有)
	}

	if err := json.Unmarshal([]byte(line), &eve); err != nil {
		log.Printf("Failed to parse Suricata JSON log: %v", err)
		return
	}

	// 只处理 alert 类型的日志
	if eve.EventType != "alert" {
		return
	}

	// 解析时间戳 (Suricata EVE JSON 时间格式类似于 2026-01-20T11:26:00.000000+0000)
	// 使用 RFC3339Nano 兼容的格式化解析
	t, err := time.Parse("2006-01-02T15:04:05.999999Z0700", eve.Timestamp)
	var timestamp int64
	if err != nil {
		// 如果解析失败，尝试另一种常见格式
		t, err = time.Parse("2006-01-02T15:04:05.999999-0700", eve.Timestamp)
		if err != nil {
			log.Printf("Failed to parse timestamp %s: %v", eve.Timestamp, err)
			timestamp = time.Now().UnixMilli()
		} else {
			timestamp = t.UnixMilli()
		}
	} else {
		timestamp = t.UnixMilli()
	}

	// 转换告警等级 (Severity)
	// Suricata 默认: 1:High, 2:Medium, 3:Low, 4:Info/Very Low
	// 按照我们 proto 定义的规范转换
	severityStr := "low"
	switch eve.Alert.Severity {
	case 1:
		severityStr = "high"
	case 2:
		severityStr = "medium"
	case 3:
		severityStr = "low"
	case 4:
		severityStr = "info"
	default:
		severityStr = "unknown"
	}

	// 构建 Protobuf 结构体
	req := &pb.AlertReportRequest{
		Sid:           fmt.Sprintf("%d", eve.Alert.SignatureID),
		Payload:       eve.Payload, // 如果 EVE JSON 配置了开启 payload 输出
		SourceIp:      eve.SrcIP,
		Timestamp:     timestamp,
		Severity:      severityStr,
		SignatureName: eve.Alert.Signature,
		AssetInfo:     "unknown", // 初始资产信息未知，由 Master 引擎补充或按需采集
	}

	atomic.AddInt64(&c.alertCount, 1)

	// 回调上报函数
	reportFunc(req)
}
