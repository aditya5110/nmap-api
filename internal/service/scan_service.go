package service

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"time"

	"nmap-api/internal/domain"
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
		normalized, _, err := normalizeTarget(strings.TrimSpace(target))
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
		normalized, targetType, err := normalizeTarget(target)
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

func normalizeTarget(target string) (normalized, targetType string, err error) {
	if target == "" || strings.TrimSpace(target) != target {
		return "", "", fmt.Errorf("target must be non-empty and must not contain surrounding whitespace")
	}
	if ip := net.ParseIP(target); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), "ip", nil
		}
		return ip.String(), "ip", nil
	}
	if looksLikeMalformedIPv4(target) {
		return "", "", fmt.Errorf("malformed IPv4 address")
	}

	hostname := strings.TrimSuffix(strings.ToLower(target), ".")
	if len(hostname) == 0 || len(hostname) > 253 {
		return "", "", fmt.Errorf("hostname length is invalid")
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", "", fmt.Errorf("hostname label is invalid")
		}
		for _, character := range label {
			if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-') {
				return "", "", fmt.Errorf("hostname contains an invalid character")
			}
		}
	}
	return hostname, "hostname", nil
}

func looksLikeMalformedIPv4(value string) bool {
	if !strings.Contains(value, ".") {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && character != '.' {
			return false
		}
	}
	return true
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
