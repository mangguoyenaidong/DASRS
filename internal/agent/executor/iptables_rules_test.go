package executor

import (
	"reflect"
	"testing"
)

func TestParseBlockedSources(t *testing.T) {
	output := `-P INPUT ACCEPT
-A INPUT -s 198.51.100.20/32 -j DROP
-A INPUT -s 203.0.113.7/32 -j ACCEPT
-A FORWARD -s 192.0.2.6/32 -j DROP
-A INPUT -s 2001:db8::10/128 -j DROP
-A INPUT -s 198.51.100.20/32 -j DROP
-A INPUT -s 10.0.0.0/24 -j DROP`

	got := parseBlockedSources(output)
	want := []string{"198.51.100.20", "2001:db8::10"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseBlockedSources() = %v, want %v", got, want)
	}
}
