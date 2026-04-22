package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"time"

	pb "security-response-system/internal/proto"

	"github.com/hpcloud/tail"
)

// SuricataCollector tails eve.json and forwards alert events to master.
type SuricataCollector struct {
	filePath   string
	localIP    string
	monitorIP  string
	offsetFile string
	tail       *tail.Tail
	trafficCtx TrafficContextProvider
	ctx        context.Context
	cancel     context.CancelFunc
	alertCount int64
}

func NewSuricataCollector(filePath, localIP, monitorIP string) *SuricataCollector {
	ctx, cancel := context.WithCancel(context.Background())
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

func (c *SuricataCollector) GetAlertCount() int64 {
	return atomic.LoadInt64(&c.alertCount)
}

func (c *SuricataCollector) SetTrafficContextProvider(provider TrafficContextProvider) {
	c.trafficCtx = provider
}

func (c *SuricataCollector) Start(reportFunc func(*pb.AlertReportRequest)) error {
	seekInfo := c.calculateStartOffset()

	var err error
	c.tail, err = tail.TailFile(c.filePath, tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: false,
		Poll:      true,
		Location:  seekInfo,
	})
	if err != nil {
		return fmt.Errorf("failed to tail file %s: %w", c.filePath, err)
	}

	log.Printf("Started Suricata collector on %s (Offset: %v)", c.filePath, seekInfo.Offset)

	go func() {
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

func (c *SuricataCollector) calculateStartOffset() *tail.SeekInfo {
	defaultSeek := &tail.SeekInfo{Offset: 0, Whence: os.SEEK_SET}

	data, err := os.ReadFile(c.offsetFile)
	if err != nil {
		return defaultSeek
	}

	var savedOffset int64
	if _, err := fmt.Sscanf(string(data), "%d", &savedOffset); err != nil {
		return defaultSeek
	}

	info, err := os.Stat(c.filePath)
	if err != nil {
		return defaultSeek
	}

	if savedOffset > info.Size() {
		log.Printf("Warning: Saved offset %d is greater than file size %d. Resetting to 0.", savedOffset, info.Size())
		return defaultSeek
	}

	return &tail.SeekInfo{Offset: savedOffset, Whence: os.SEEK_SET}
}

func (c *SuricataCollector) saveOffset() {
	if c.tail == nil {
		return
	}
	offset, err := c.tail.Tell()
	if err != nil {
		return
	}
	_ = os.WriteFile(c.offsetFile, []byte(fmt.Sprintf("%d", offset)), 0644)
}

func (c *SuricataCollector) Stop() {
	if c.trafficCtx != nil {
		c.trafficCtx.Stop()
	}
	c.cancel()
}

func (c *SuricataCollector) cleanup() {
	log.Println("Stopping Suricata collector and saving final offset...")
	c.saveOffset()
	if c.tail != nil {
		c.tail.Stop()
		c.tail.Cleanup()
	}
}

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
		Payload          string `json:"payload"`
		PayloadPrintable string `json:"payload_printable"`
		Packet           string `json:"packet"`
	}

	if err := json.Unmarshal([]byte(line), &eve); err != nil {
		return
	}
	if eve.EventType != "alert" {
		return
	}

	if !c.inMonitoredScope(eve.SrcIP, eve.DestIP) {
		log.Printf("Skipping alert outside monitored scope: src=%s dest=%s local=%s monitor_ip=%s sid=%d", eve.SrcIP, eve.DestIP, c.localIP, c.monitorIP, eve.Alert.SignatureID)
		return
	}

	t, err := time.Parse(time.RFC3339Nano, eve.Timestamp)
	var ts int64
	if err != nil {
		t, _ = time.Parse("2006-01-02T15:04:05.999999-0700", eve.Timestamp)
		ts = t.UnixMilli()
	} else {
		ts = t.UnixMilli()
	}

	severity := "low"
	switch eve.Alert.Severity {
	case 1:
		severity = "high"
	case 2:
		severity = "medium"
	case 3:
		severity = "low"
	}

	req := &pb.AlertReportRequest{
		Sid:           fmt.Sprintf("%d", eve.Alert.SignatureID),
		Payload:       selectAlertPayload(eve.Payload, eve.PayloadPrintable, eve.Packet),
		SourceIp:      eve.SrcIP,
		AssetInfo:     fmt.Sprintf("Agent: %s | Monitor: %s | DestIP: %s", c.localIP, c.monitorIP, eve.DestIP),
		Timestamp:     ts,
		Severity:      severity,
		SignatureName: eve.Alert.Signature,
	}

	if req.Payload == "" {
		log.Printf("Alert payload missing in eve.json: sid=%s src=%s dest=%s", req.Sid, req.SourceIp, eve.DestIP)
	}
	if c.trafficCtx != nil {
		if contextSummary := c.trafficCtx.DescribeAround(eve.SrcIP, eve.DestIP, t.Add(0)); contextSummary != "" {
			req.AssetInfo = req.AssetInfo + "\nTraffic Context:\n" + contextSummary
		}
	}

	atomic.AddInt64(&c.alertCount, 1)
	reportFunc(req)
}

func (c *SuricataCollector) inMonitoredScope(srcIP, destIP string) bool {
	scopeIPs := make([]string, 0, 2)
	for _, ip := range []string{strings.TrimSpace(c.monitorIP), strings.TrimSpace(c.localIP)} {
		if ip == "" || ip == "0.0.0.0" {
			continue
		}
		scopeIPs = append(scopeIPs, ip)
	}

	if len(scopeIPs) == 0 {
		return true
	}

	for _, ip := range scopeIPs {
		if srcIP == ip || destIP == ip {
			return true
		}
	}

	return false
}

func selectAlertPayload(payload, payloadPrintable, packet string) string {
	switch {
	case payload != "":
		return payload
	case payloadPrintable != "":
		return payloadPrintable
	case packet != "":
		return packet
	default:
		return ""
	}
}
