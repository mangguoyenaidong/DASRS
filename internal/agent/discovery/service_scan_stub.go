//go:build !linux

package discovery

import "context"

type LocalServiceScanner struct{}

func NewLocalServiceScanner() Scanner {
	return &LocalServiceScanner{}
}

func (s *LocalServiceScanner) Scan(ctx context.Context) ([]ServiceRecord, error) {
	return []ServiceRecord{}, nil
}
