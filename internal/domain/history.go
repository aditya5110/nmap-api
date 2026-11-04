package domain

import "time"

type ScanHistory struct {
	ScanID       int64              `json:"scan_id"`
	StartedAt    *time.Time         `json:"started_at"`
	FinishedAt   *time.Time         `json:"finished_at"`
	Status       string             `json:"status"`
	ResolvedIPs  []string           `json:"resolved_ips"`
	Ports        []ObservedScanPort `json:"ports"`
	HostStatuses map[string]string  `json:"-"`
}

type ObservedScanPort struct {
	ResolvedIP string  `json:"resolved_ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	State      string  `json:"state"`
	Service    *string `json:"service"`
	Reason     *string `json:"reason,omitempty"`
}
