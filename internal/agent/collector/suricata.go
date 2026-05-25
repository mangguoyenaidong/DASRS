package collector

import (
	"bufio"
	"context"
	"crypto/sha256"
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
	filePath       string
	localIP        string
	monitorIP      string
	readExisting   bool
	offsetFile     string
	tail           *tail.Tail
	trafficCtx     TrafficContextProvider
	ctx            context.Context
	cancel         context.CancelFunc
	retryInterval  time.Duration
	committedBytes int64
	fileIdentity   string
	nextIdentityAt time.Time
	alertCount     int64
}

type offsetCheckpoint struct {
	Offset       int64  `json:"offset"`
	FileIdentity string `json:"file_identity,omitempty"`
}

func NewSuricataCollector(filePath, localIP, monitorIP string, readExisting ...bool) *SuricataCollector {
	ctx, cancel := context.WithCancel(context.Background())
	cleanPath := strings.NewReplacer("/", "_", "\\", "_", ":", "_").Replace(filePath)
	offsetFile := fmt.Sprintf(".suricata_%s.offset", cleanPath)
	replayHistory := len(readExisting) > 0 && readExisting[0]

	return &SuricataCollector{
		filePath:       filePath,
		localIP:        localIP,
		monitorIP:      monitorIP,
		readExisting:   replayHistory,
		offsetFile:     offsetFile,
		ctx:            ctx,
		cancel:         cancel,
		retryInterval:  2 * time.Second,
		nextIdentityAt: time.Now(),
	}
}

func (c *SuricataCollector) GetAlertCount() int64 {
	return atomic.LoadInt64(&c.alertCount)
}

func (c *SuricataCollector) SetTrafficContextProvider(provider TrafficContextProvider) {
	c.trafficCtx = provider
}

func (c *SuricataCollector) Start(reportFunc func(*pb.AlertReportRequest) error) error {
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

	log.Printf("Started Suricata collector on %s (offset=%d whence=%d read_existing=%v)", c.filePath, seekInfo.Offset, seekInfo.Whence, c.readExisting)

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
				if !c.processLine(line.Text, reportFunc) {
					c.cleanup()
					return
				}
				c.commitLine(line.Text)
			}
		}
	}()

	return nil
}

func (c *SuricataCollector) calculateStartOffset() *tail.SeekInfo {
	defaultSeek := &tail.SeekInfo{Offset: 0, Whence: os.SEEK_SET}
	currentIdentity := identifyLogFile(c.filePath)
	c.fileIdentity = currentIdentity
	c.nextIdentityAt = time.Now().Add(time.Second)

	data, err := os.ReadFile(c.offsetFile)
	if err != nil {
		if !c.readExisting {
			if info, statErr := os.Stat(c.filePath); statErr == nil {
				atomic.StoreInt64(&c.committedBytes, info.Size())
				return &tail.SeekInfo{Offset: 0, Whence: os.SEEK_END}
			}
		}
		atomic.StoreInt64(&c.committedBytes, 0)
		return defaultSeek
	}

	var checkpoint offsetCheckpoint
	if err := json.Unmarshal(data, &checkpoint); err != nil {
		if _, scanErr := fmt.Sscanf(string(data), "%d", &checkpoint.Offset); scanErr != nil {
			atomic.StoreInt64(&c.committedBytes, 0)
			return defaultSeek
		}
	}

	info, err := os.Stat(c.filePath)
	if err != nil {
		atomic.StoreInt64(&c.committedBytes, 0)
		return defaultSeek
	}

	if checkpoint.FileIdentity != "" && currentIdentity != "" && checkpoint.FileIdentity != currentIdentity {
		log.Printf("Detected rotated Suricata log file. Resetting saved offset to read the new file safely.")
		atomic.StoreInt64(&c.committedBytes, 0)
		return defaultSeek
	}

	if checkpoint.Offset > info.Size() {
		log.Printf("Warning: Saved offset %d is greater than file size %d. Resetting to 0.", checkpoint.Offset, info.Size())
		atomic.StoreInt64(&c.committedBytes, 0)
		return defaultSeek
	}

	atomic.StoreInt64(&c.committedBytes, checkpoint.Offset)
	return &tail.SeekInfo{Offset: checkpoint.Offset, Whence: os.SEEK_SET}
}

func (c *SuricataCollector) saveOffset() {
	checkpoint := offsetCheckpoint{
		Offset:       atomic.LoadInt64(&c.committedBytes),
		FileIdentity: c.fileIdentity,
	}
	data, err := json.Marshal(checkpoint)
	if err != nil {
		return
	}
	_ = os.WriteFile(c.offsetFile, data, 0644)
}

func (c *SuricataCollector) commitLine(line string) {
	if now := time.Now(); !now.Before(c.nextIdentityAt) || c.fileIdentity == "" {
		currentIdentity := identifyLogFile(c.filePath)
		if currentIdentity != "" && c.fileIdentity != "" && currentIdentity != c.fileIdentity {
			log.Printf("Detected rotated Suricata log while collecting. Resetting committed offset for the new file.")
			atomic.StoreInt64(&c.committedBytes, 0)
		}
		if currentIdentity != "" {
			c.fileIdentity = currentIdentity
		}
		c.nextIdentityAt = now.Add(time.Second)
	}
	atomic.AddInt64(&c.committedBytes, int64(len([]byte(line))+1))
}

func identifyLogFile(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer file.Close()

	firstLine, err := bufio.NewReader(file).ReadString('\n')
	if err != nil || firstLine == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(firstLine))
	return fmt.Sprintf("%x", sum[:])
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

func (c *SuricataCollector) processLine(line string, reportFunc func(*pb.AlertReportRequest) error) bool {
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
		log.Printf("Skipping invalid eve.json line: %v", err)
		return true
	}
	if eve.EventType != "alert" {
		return true
	}

	if !c.inMonitoredScope(eve.SrcIP, eve.DestIP) {
		log.Printf("Skipping alert outside monitored scope: src=%s dest=%s local=%s monitor_ip=%s sid=%d", eve.SrcIP, eve.DestIP, c.localIP, c.monitorIP, eve.Alert.SignatureID)
		return true
	}

	t, err := time.Parse(time.RFC3339Nano, eve.Timestamp)
	if err != nil {
		t, err = time.Parse("2006-01-02T15:04:05.999999-0700", eve.Timestamp)
		if err != nil {
			log.Printf("Skipping alert with invalid eve.json timestamp %q: %v", eve.Timestamp, err)
			return true
		}
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
		DestIp:        eve.DestIP,
		AssetInfo:     fmt.Sprintf("Agent: %s | Monitor: %s | DestIP: %s", c.localIP, c.monitorIP, eve.DestIP),
		Timestamp:     t.UnixMilli(),
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

	for {
		if err := reportFunc(req); err == nil {
			atomic.AddInt64(&c.alertCount, 1)
			return true
		} else {
			log.Printf("Failed to report Suricata alert sid=%s src=%s dest=%s; retrying in %s: %v", req.Sid, req.SourceIp, req.DestIp, c.retryInterval, err)
		}

		timer := time.NewTimer(c.retryInterval)
		select {
		case <-c.ctx.Done():
			timer.Stop()
			return false
		case <-timer.C:
		}
	}
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
