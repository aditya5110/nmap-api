package nmap

import "time"

// ScanResult contains the requested target and all host observations from one Nmap run.
type ScanResult struct {
	Target     string
	StartedAt  *time.Time
	FinishedAt *time.Time
	Hosts      []HostResult
}

// HostResult contains one result per distinct resolved IP address.
type HostResult struct {
	ResolvedIP *string
	Status     *string
	StartedAt  *time.Time
	FinishedAt *time.Time
	Ports      []Port
}

// Port contains one observed port and its Nmap state metadata.
type Port struct {
	Number      int
	Protocol    string
	State       string
	ServiceName *string
	Reason      *string
}
