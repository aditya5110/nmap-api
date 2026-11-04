package domain

import "time"

type ScanRequest struct {
	ID          int64
	RequestUUID string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Status      string
}

type ScanJob struct {
	ID             int64
	RequestID      int64
	TargetValue    string
	TargetType     string
	Status         string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	StartedAt      *time.Time
	FinishedAt     *time.Time
	TimeoutSeconds int
	Attempts       int
	ErrorMessage   *string
	LeaseExpiresAt *time.Time
}

type ScanResult struct {
	ID          int64
	JobID       int64
	TargetValue string
	HostIP      string
	HostStatus  string
	StartedAt   time.Time
	FinishedAt  time.Time
	RawXML      string
}

type ScanPort struct {
	ID           int64
	ScanResultID int64
	Port         int
	Protocol     string
	State        string
	ServiceName  *string
	Reason       *string
}
