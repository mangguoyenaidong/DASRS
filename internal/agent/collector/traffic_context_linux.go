//go:build linux

package collector

import (
	"bytes"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	trafficContextWindow     = 10 * time.Second
	trafficContextQueryRange = 5 * time.Second
	trafficContextMaxPayload = 768
	trafficContextMaxItems   = 8
)

type trafficEvent struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Summary   string
}

type LiveTrafficContextCollector struct {
	localIP   string
	monitorIP string
	handle    *pcap.Handle
	stopChan  chan struct{}
	wg        sync.WaitGroup

	mu     sync.Mutex
	events []trafficEvent
}

func NewTrafficContextCollector(localIP, monitorIP string) TrafficContextProvider {
	return &LiveTrafficContextCollector{
		localIP:   strings.TrimSpace(localIP),
		monitorIP: strings.TrimSpace(monitorIP),
		stopChan:  make(chan struct{}),
	}
}

func (c *LiveTrafficContextCollector) Start() error {
	device, err := c.findDevice()
	if err != nil {
		return err
	}

	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open pcap on %s: %w", device, err)
	}

	filterHost := c.monitorIP
	if filterHost == "" {
		filterHost = c.localIP
	}
	filter := "tcp and (port 80 or port 8080)"
	if filterHost != "" {
		filter = fmt.Sprintf("dst host %s and %s", filterHost, filter)
	}
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return fmt.Errorf("set pcap filter %q: %w", filter, err)
	}

	c.handle = handle
	c.wg.Add(1)
	go c.captureLoop(handle)
	log.Printf("Traffic context collector started on %s with filter: %s", device, filter)
	return nil
}

func (c *LiveTrafficContextCollector) Stop() {
	select {
	case <-c.stopChan:
	default:
		close(c.stopChan)
	}
	if c.handle != nil {
		c.handle.Close()
	}
	c.wg.Wait()
}

func (c *LiveTrafficContextCollector) DescribeAround(sourceIP, destIP string, ts time.Time) string {
	start := ts.Add(-trafficContextQueryRange)
	end := ts.Add(trafficContextQueryRange)

	c.mu.Lock()
	defer c.mu.Unlock()

	c.pruneLocked(time.Now())

	matches := make([]trafficEvent, 0, trafficContextMaxItems)
	for _, item := range c.events {
		if item.Timestamp.Before(start) || item.Timestamp.After(end) {
			continue
		}
		if item.SrcIP != sourceIP || item.DstIP != destIP {
			continue
		}
		matches = append(matches, item)
	}
	if len(matches) == 0 {
		return ""
	}

	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Timestamp.Before(matches[j].Timestamp)
	})
	if len(matches) > trafficContextMaxItems {
		matches = matches[:trafficContextMaxItems]
	}

	lines := []string{fmt.Sprintf("matched packets: %d", len(matches))}
	for _, item := range matches {
		lines = append(lines, fmt.Sprintf(
			"%s %s:%d -> %s:%d | %s",
			item.Timestamp.Format("15:04:05.000"),
			item.SrcIP,
			item.SrcPort,
			item.DstIP,
			item.DstPort,
			item.Summary,
		))
	}
	return strings.Join(lines, "\n")
}

func (c *LiveTrafficContextCollector) captureLoop(handle *pcap.Handle) {
	defer c.wg.Done()
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := source.Packets()

	for {
		select {
		case <-c.stopChan:
			return
		case packet, ok := <-packets:
			if !ok {
				return
			}
			c.processPacket(packet)
		}
	}
}

func (c *LiveTrafficContextCollector) processPacket(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	ip := ipLayer.(*layers.IPv4)
	tcp := tcpLayer.(*layers.TCP)
	payload := normalizePayload(tcp.Payload)
	if payload == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.pruneLocked(time.Now())
	c.events = append(c.events, trafficEvent{
		Timestamp: packet.Metadata().Timestamp,
		SrcIP:     ip.SrcIP.String(),
		DstIP:     ip.DstIP.String(),
		SrcPort:   uint16(tcp.SrcPort),
		DstPort:   uint16(tcp.DstPort),
		Summary:   summarizePayload(payload),
	})
}

func (c *LiveTrafficContextCollector) pruneLocked(now time.Time) {
	threshold := now.Add(-trafficContextWindow)
	idx := 0
	for _, item := range c.events {
		if item.Timestamp.After(threshold) {
			c.events[idx] = item
			idx++
		}
	}
	c.events = c.events[:idx]
}

func (c *LiveTrafficContextCollector) findDevice() (string, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("find pcap devices: %w", err)
	}

	targets := []string{c.localIP, c.monitorIP}
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		for _, dev := range devs {
			for _, addr := range dev.Addresses {
				if addr.IP != nil && addr.IP.To4() != nil && addr.IP.String() == target {
					return dev.Name, nil
				}
			}
		}
	}

	for _, dev := range devs {
		for _, addr := range dev.Addresses {
			if addr.IP != nil && addr.IP.To4() != nil && !addr.IP.IsLoopback() {
				return dev.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no usable pcap device found")
}

func normalizePayload(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	if len(payload) > trafficContextMaxPayload {
		payload = payload[:trafficContextMaxPayload]
	}

	payload = bytes.TrimSpace(payload)
	if len(payload) == 0 {
		return ""
	}

	if !looksLikeHTTPPayload(payload) && !containsSuspiciousKeyword(string(payload)) {
		return ""
	}
	return strings.TrimSpace(string(payload))
}

func looksLikeHTTPPayload(payload []byte) bool {
	text := strings.ToUpper(string(payload))
	for _, prefix := range []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH "} {
		if strings.HasPrefix(text, prefix) {
			return true
		}
	}
	return false
}

func containsSuspiciousKeyword(payload string) bool {
	low := strings.ToLower(payload)
	for _, keyword := range []string{"/etc/passwd", "union select", "cmd=", "wget ", "curl ", "bash -c", "../"} {
		if strings.Contains(low, keyword) {
			return true
		}
	}
	return false
}

func summarizePayload(payload string) string {
	lines := strings.Split(payload, "\n")
	firstLine := strings.TrimSpace(lines[0])
	host := ""
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			host = strings.TrimSpace(strings.TrimPrefix(line, "Host:"))
			break
		}
	}

	summary := firstLine
	if host != "" {
		summary += " | host=" + host
	}

	low := strings.ToLower(payload)
	hits := make([]string, 0, 4)
	for _, keyword := range []string{"/etc/passwd", "union select", "cmd=", "wget ", "curl ", "bash -c", "../"} {
		if strings.Contains(low, keyword) {
			hits = append(hits, keyword)
		}
	}
	if len(hits) > 0 {
		summary += " | hits=" + strings.Join(hits, ",")
	}

	return strings.TrimSpace(summary)
}
