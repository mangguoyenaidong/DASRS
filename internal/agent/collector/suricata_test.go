package collector

import "testing"

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
