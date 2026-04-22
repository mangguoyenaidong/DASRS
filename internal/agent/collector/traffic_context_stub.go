//go:build !linux

package collector

import "time"

type NoopTrafficContextCollector struct{}

func NewTrafficContextCollector(localIP, monitorIP string) TrafficContextProvider {
	return &NoopTrafficContextCollector{}
}

func (c *NoopTrafficContextCollector) Start() error { return nil }

func (c *NoopTrafficContextCollector) Stop() {}

func (c *NoopTrafficContextCollector) DescribeAround(sourceIP, destIP string, ts time.Time) string {
	return ""
}
