package service

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"nmap-api/internal/domain"
	targetvalidation "nmap-api/internal/target"
	"nmap-api/internal/worker"
)

type ScanRepository interface {
	CreateScanRequestWithJobs(context.Context, domain.ScanRequest, []domain.ScanJob) (int64, error)
}

type ValidationError struct {
	Code    string
	Message string
}

func (e *ValidationError) Error() string { return e.Message }

type ScanSubmission struct {
	Targets        []string `json:"targets"`
	TimeoutSeconds *int     `json:"timeout_seconds,omitempty"`
}

type AcceptedScan struct {
	RequestID string           `json:"request_id"`
	Status    string           `json:"status"`
	Targets   []AcceptedTarget `json:"targets"`
}

type AcceptedTarget struct {
	Target string `json:"target"`
	Status string `json:"status"`
}

type ScanService struct {
	repository     ScanRepository
	maxBatchSize   int
	defaultTimeout int
	allowedTargets map[string]struct{}
}

func NewScanService(repository ScanRepository, maxBatchSize, defaultTimeout int, allowedTargets []string) (*ScanService, error) {
	maxTimeoutSeconds := int(worker.MaxScanTimeout / time.Second)
	if repository == nil {
		return nil, fmt.Errorf("scan repository is required")
	}
	if maxBatchSize <= 0 {
		return nil, fmt.Errorf("maximum batch size must be greater than zero")
	}
	if defaultTimeout <= 0 || defaultTimeout > maxTimeoutSeconds {
		return nil, fmt.Errorf("default scan timeout must be between 1 and %d seconds", maxTimeoutSeconds)
	}

	allowed := make(map[string]struct{}, len(allowedTargets))
	for _, target := range allowedTargets {
		normalized, _, err := targetvalidation.Normalize(strings.TrimSpace(target))
		if err != nil {
			return nil, fmt.Errorf("invalid SCAN_ALLOWED_TARGETS entry %q: %w", target, err)
		}
		allowed[normalized] = struct{}{}
	}

	return &ScanService{
		repository:     repository,
		maxBatchSize:   maxBatchSize,
		defaultTimeout: defaultTimeout,
		allowedTargets: allowed,
	}, nil
}

func (s *ScanService) Submit(ctx context.Context, submission ScanSubmission) (AcceptedScan, error) {
	if len(submission.Targets) == 0 {
		return AcceptedScan{}, &ValidationError{Code: "INVALID_REQUEST", Message: "at least one target is required"}
	}
	if len(submission.Targets) > s.maxBatchSize {
		return AcceptedScan{}, &ValidationError{Code: "BATCH_TOO_LARGE", Message: fmt.Sprintf("batch exceeds the maximum of %d targets", s.maxBatchSize)}
	}

	timeout := s.defaultTimeout
	if submission.TimeoutSeconds != nil {
		timeout = *submission.TimeoutSeconds
	}
	if timeout <= 0 || timeout > int(worker.MaxScanTimeout/time.Second) {
		return AcceptedScan{}, &ValidationError{Code: "INVALID_TIMEOUT", Message: fmt.Sprintf("timeout_seconds must be between 1 and %d", int(worker.MaxScanTimeout.Seconds()))}
	}

	jobs := make([]domain.ScanJob, 0, len(submission.Targets))
	acceptedTargets := make([]AcceptedTarget, 0, len(submission.Targets))
	for _, target := range submission.Targets {
		normalized, targetType, err := targetvalidation.Normalize(target)
		if err != nil {
			return AcceptedScan{}, &ValidationError{Code: "INVALID_TARGET", Message: fmt.Sprintf("target %q is not a valid IPv4 address, IPv6 address, or hostname", target)}
		}
		if _, ok := s.allowedTargets[normalized]; !ok {
			return AcceptedScan{}, &ValidationError{Code: "TARGET_NOT_ALLOWED", Message: fmt.Sprintf("target %q is not in SCAN_ALLOWED_TARGETS", target)}
		}
		jobs = append(jobs, domain.ScanJob{
			TargetValue:    target,
			TargetType:     targetType,
			Status:         "pending",
			TimeoutSeconds: timeout,
		})
		acceptedTargets = append(acceptedTargets, AcceptedTarget{Target: target, Status: "pending"})
	}

	requestID, err := newRequestUUID()
	if err != nil {
		return AcceptedScan{}, fmt.Errorf("generate scan request ID: %w", err)
	}
	if _, err := s.repository.CreateScanRequestWithJobs(ctx, domain.ScanRequest{
		RequestUUID: requestID,
		Status:      "pending",
	}, jobs); err != nil {
		return AcceptedScan{}, fmt.Errorf("persist scan request: %w", err)
	}

	return AcceptedScan{RequestID: requestID, Status: "accepted", Targets: acceptedTargets}, nil
}

func newRequestUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}
