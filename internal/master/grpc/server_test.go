package grpc

import "testing"

func TestParseCommandStreamRegistrationUsesReportedAgentIP(t *testing.T) {
	hostname, ip := parseCommandStreamRegistration(
		`{"hostname":"vm-agent","ip":"192.168.41.136"}`,
		"172.18.0.3",
	)

	if hostname != "vm-agent" {
		t.Fatalf("hostname = %q, want %q", hostname, "vm-agent")
	}
	if ip != "192.168.41.136" {
		t.Fatalf("ip = %q, want %q", ip, "192.168.41.136")
	}
}

func TestParseCommandStreamRegistrationPreservesLegacyMessage(t *testing.T) {
	hostname, ip := parseCommandStreamRegistration("legacy-agent", "10.0.0.8")

	if hostname != "legacy-agent" {
		t.Fatalf("hostname = %q, want %q", hostname, "legacy-agent")
	}
	if ip != "10.0.0.8" {
		t.Fatalf("ip = %q, want %q", ip, "10.0.0.8")
	}
}
