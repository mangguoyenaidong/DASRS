package collector

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	pb "security-response-system/internal/proto"
)

func TestSuricataCollectorInMonitoredScopeWithMonitorIPMatchesSourceOrDest(t *testing.T) {
	c := NewSuricataCollector("eve.json", "192.168.41.136", "192.168.41.136")

	cases := []struct {
		name   string
		srcIP  string
		destIP string
		want   bool
	}{
		{name: "inbound to monitored host", srcIP: "192.168.41.10", destIP: "192.168.41.136", want: true},
		{name: "outbound from monitored host", srcIP: "192.168.41.136", destIP: "192.168.41.10", want: true},
		{name: "unrelated traffic", srcIP: "192.168.41.10", destIP: "192.168.41.20", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.inMonitoredScope(tc.srcIP, tc.destIP); got != tc.want {
				t.Fatalf("inMonitoredScope(%q, %q) = %v, want %v", tc.srcIP, tc.destIP, got, tc.want)
			}
		})
	}
}

func TestSuricataCollectorInMonitoredScopeAllowsAllWhenScopeUnset(t *testing.T) {
	c := NewSuricataCollector("eve.json", "", "")

	if !c.inMonitoredScope("10.0.0.1", "10.0.0.2") {
		t.Fatal("expected collector to allow alerts when no scope IPs are configured")
	}
}

func TestSuricataCollectorProcessLineRetriesAndIncludesDestIP(t *testing.T) {
	c := NewSuricataCollector("eve.json", "", "")
	c.retryInterval = time.Millisecond

	line := `{"timestamp":"2026-04-12T05:39:03.667611+0000","event_type":"alert","src_ip":"192.0.2.5","dest_ip":"198.51.100.10","alert":{"signature_id":2210002,"signature":"test alert","severity":1},"payload_printable":"sample"}`
	attempts := 0
	var got *pb.AlertReportRequest
	processed := c.processLine(line, func(req *pb.AlertReportRequest) error {
		attempts++
		got = req
		if attempts == 1 {
			return errors.New("master offline")
		}
		return nil
	})

	if !processed {
		t.Fatal("expected line to be processed after successful retry")
	}
	if attempts != 2 {
		t.Fatalf("report attempts = %d, want 2", attempts)
	}
	if got == nil || got.GetDestIp() != "198.51.100.10" {
		t.Fatalf("reported dest ip = %q, want %q", got.GetDestIp(), "198.51.100.10")
	}
	if got.GetTimestamp() == 0 {
		t.Fatal("expected Suricata timestamp to be parsed")
	}
	if c.GetAlertCount() != 1 {
		t.Fatalf("alert count = %d, want 1", c.GetAlertCount())
	}
}

func TestSuricataCollectorStartOffsetSkipsExistingFileUnlessReplayEnabled(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "eve.json")
	content := []byte("{\"event_type\":\"stats\"}\n")
	if err := os.WriteFile(logPath, content, 0644); err != nil {
		t.Fatal(err)
	}

	c := NewSuricataCollector(logPath, "", "")
	c.offsetFile = filepath.Join(dir, "current.offset")
	seek := c.calculateStartOffset()
	if seek.Whence != os.SEEK_END {
		t.Fatalf("default initial seek whence = %d, want SEEK_END", seek.Whence)
	}
	if got := atomic.LoadInt64(&c.committedBytes); got != int64(len(content)) {
		t.Fatalf("default committed offset = %d, want %d", got, len(content))
	}

	replay := NewSuricataCollector(logPath, "", "", true)
	replay.offsetFile = filepath.Join(dir, "replay.offset")
	replaySeek := replay.calculateStartOffset()
	if replaySeek.Whence != os.SEEK_SET || replaySeek.Offset != 0 {
		t.Fatalf("replay initial seek = %+v, want beginning of file", replaySeek)
	}
}

func TestSuricataCollectorSavesOnlyCommittedLines(t *testing.T) {
	c := NewSuricataCollector("eve.json", "", "")
	c.offsetFile = filepath.Join(t.TempDir(), "collector.offset")
	c.commitLine("abc")
	c.saveOffset()

	data, err := os.ReadFile(c.offsetFile)
	if err != nil {
		t.Fatal(err)
	}
	var checkpoint offsetCheckpoint
	if err := json.Unmarshal(data, &checkpoint); err != nil {
		t.Fatal(err)
	}
	if checkpoint.Offset != 4 {
		t.Fatalf("saved offset = %d, want %d", checkpoint.Offset, 4)
	}
}

func TestSuricataCollectorResetsCheckpointAfterLogRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "eve.json")
	offsetPath := filepath.Join(dir, "collector.offset")
	if err := os.WriteFile(logPath, []byte("old-first-line\nold-second-line\n"), 0644); err != nil {
		t.Fatal(err)
	}

	original := NewSuricataCollector(logPath, "", "", true)
	original.offsetFile = offsetPath
	original.calculateStartOffset()
	original.commitLine("old-first-line")
	original.saveOffset()

	if err := os.WriteFile(logPath, []byte("new-first-line\nnew-second-line\n"), 0644); err != nil {
		t.Fatal(err)
	}

	afterRotation := NewSuricataCollector(logPath, "", "")
	afterRotation.offsetFile = offsetPath
	seek := afterRotation.calculateStartOffset()
	if seek.Whence != os.SEEK_SET || seek.Offset != 0 {
		t.Fatalf("rotated file initial seek = %+v, want beginning of new file", seek)
	}
}

func TestSuricataCollectorResetsCommittedOffsetDuringActiveRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "eve.json")
	if err := os.WriteFile(logPath, []byte("old-first-line\n"), 0644); err != nil {
		t.Fatal(err)
	}

	c := NewSuricataCollector(logPath, "", "", true)
	c.offsetFile = filepath.Join(dir, "collector.offset")
	c.calculateStartOffset()
	c.commitLine("old-first-line")

	if err := os.WriteFile(logPath, []byte("new-first-line\n"), 0644); err != nil {
		t.Fatal(err)
	}
	c.nextIdentityAt = time.Time{}
	c.commitLine("new-first-line")

	if got, want := atomic.LoadInt64(&c.committedBytes), int64(len("new-first-line\n")); got != want {
		t.Fatalf("active-rotation committed offset = %d, want %d", got, want)
	}
}
