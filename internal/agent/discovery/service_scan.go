package discovery

import (
	"context"
	"sort"
)

// ServiceRecord describes one local listening service discovered by the agent.
type ServiceRecord struct {
	Name      string `json:"name"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	Process   string `json:"process"`
	Listen    string `json:"listen"`
	Status    string `json:"status"`
	Source    string `json:"source"`
	UpdatedAt string `json:"updated_at"`
}

// Scanner discovers local listening services.
type Scanner interface {
	Scan(ctx context.Context) ([]ServiceRecord, error)
}

func normalizeRecords(records []ServiceRecord) []ServiceRecord {
	sort.Slice(records, func(i, j int) bool {
		if records[i].Port == records[j].Port {
			if records[i].Protocol == records[j].Protocol {
				return records[i].Name < records[j].Name
			}
			return records[i].Protocol < records[j].Protocol
		}
		return records[i].Port < records[j].Port
	})
	return records
}
