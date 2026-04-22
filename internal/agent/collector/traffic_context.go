package collector

import "time"

// TrafficContextProvider keeps a short-lived packet window that can be queried
// when a Suricata alert fires.
type TrafficContextProvider interface {
	Start() error
	Stop()
	DescribeAround(sourceIP, destIP string, ts time.Time) string
}
