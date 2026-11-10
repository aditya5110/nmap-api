package worker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"nmap-api/internal/db"
	"nmap-api/internal/domain"
	"nmap-api/internal/nmap"
)

const MaxScanTimeout = 120 * time.Second

type repository interface {
	ClaimNextJob(context.Context, time.Duration) (*domain.ScanJob, error)
	RecoverExpiredJobs(context.Context) (db.LeaseRecoveryResult, error)
	UpdateClaimedJobStatus(context.Context, domain.ScanJob, string, time.Time, *string) (bool, error)
	CompleteJobWithResults(context.Context, domain.ScanJob, []domain.ScanResult, [][]domain.ScanPort) error
}

type scanRunner interface {
	RunWithTimeout(context.Context, string, time.Duration) (nmap.RunOutput, error)
}

type MetricsRecorder interface {
	RecordNmapExecution(time.Duration)
	RecordScanJobOutcomes(string, int64)
}

type Processor struct {
	repository     repository
	runner         scanRunner
	defaultTimeout time.Duration
	metrics        MetricsRecorder
}

func NewProcessor(repo repository, runner scanRunner, defaultTimeout time.Duration) (*Processor, error) {
	return NewProcessorWithMetrics(repo, runner, defaultTimeout, nil)
}

func NewProcessorWithMetrics(repo repository, runner scanRunner, defaultTimeout time.Duration, metrics MetricsRecorder) (*Processor, error) {
	if repo == nil {
		return nil, errors.New("worker repository is required")
	}
	if runner == nil {
		return nil, errors.New("worker Nmap runner is required")
	}
	if defaultTimeout <= 0 {
		return nil, errors.New("default scan timeout must be greater than zero")
	}
	if defaultTimeout > MaxScanTimeout {
		defaultTimeout = MaxScanTimeout
	}
	return &Processor{repository: repo, runner: runner, defaultTimeout: defaultTimeout, metrics: metrics}, nil
}

func (p *Processor) process(ctx context.Context, job domain.ScanJob) error {
	timeout := p.defaultTimeout
	if job.TimeoutSeconds > 0 {
		timeout = time.Duration(job.TimeoutSeconds) * time.Second
	}
	if timeout > MaxScanTimeout {
		timeout = MaxScanTimeout
	}

	nmapStarted := time.Now()
	output, err := p.runner.RunWithTimeout(ctx, job.TargetValue, timeout)
	if p.metrics != nil {
		p.metrics.RecordNmapExecution(time.Since(nmapStarted))
	}
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, nmap.ErrParentCanceled) || errors.Is(err, nmap.ErrParentDeadline) {
			return nil
		}
		status := "failed"
		if errors.Is(err, nmap.ErrScanTimeout) {
			status = "timed_out"
		}
		return p.fail(ctx, job, status, executionMessage(err, output.Stderr))
	}

	scan, err := nmap.ParseXML(job.TargetValue, output.XML)
	if err != nil {
		return p.fail(ctx, job, "failed", fmt.Sprintf("parse Nmap XML: %v", err))
	}

	results := make([]domain.ScanResult, 0, len(scan.Hosts))
	ports := make([][]domain.ScanPort, 0, len(scan.Hosts))
	for _, host := range scan.Hosts {
		if host.ResolvedIP == nil || host.Status == nil {
			return p.fail(ctx, job, "failed", "parsed host is missing required address or status")
		}
		startedAt := host.StartedAt
		if startedAt == nil {
			startedAt = scan.StartedAt
		}
		finishedAt := host.FinishedAt
		if finishedAt == nil {
			finishedAt = scan.FinishedAt
		}
		if startedAt == nil || finishedAt == nil {
			return p.fail(ctx, job, "failed", "Nmap XML is missing required scan timestamps")
		}

		results = append(results, domain.ScanResult{
			JobID:       job.ID,
			TargetValue: job.TargetValue,
			HostIP:      *host.ResolvedIP,
			HostStatus:  *host.Status,
			StartedAt:   *startedAt,
			FinishedAt:  *finishedAt,
			RawXML:      string(output.XML),
		})
		hostPorts := make([]domain.ScanPort, 0, len(host.Ports))
		for _, port := range host.Ports {
			hostPorts = append(hostPorts, domain.ScanPort{
				Port:        port.Number,
				Protocol:    port.Protocol,
				State:       port.State,
				ServiceName: port.ServiceName,
				Reason:      port.Reason,
			})
		}
		ports = append(ports, hostPorts)
	}

	if err := p.repository.CompleteJobWithResults(ctx, job, results, ports); err != nil {
		if errors.Is(err, db.ErrClaimLost) {
			return err
		}
		return p.fail(ctx, job, "failed", fmt.Sprintf("persist scan results: %v", err))
	}
	if p.metrics != nil {
		p.metrics.RecordScanJobOutcomes("completed", 1)
	}
	return nil
}

func (p *Processor) fail(ctx context.Context, job domain.ScanJob, status, message string) error {
	if ctx.Err() != nil {
		return nil
	}
	finishedAt := time.Now().UTC()
	updated, err := p.repository.UpdateClaimedJobStatus(ctx, job, status, finishedAt, &message)
	if err != nil {
		return fmt.Errorf("record %s status for scan job %d: %w (cause: %s)", status, job.ID, err, message)
	}
	if !updated {
		return fmt.Errorf("%w: job %d", db.ErrClaimLost, job.ID)
	}
	if p.metrics != nil {
		p.metrics.RecordScanJobOutcomes(status, 1)
	}
	return fmt.Errorf("scan job %d %s: %s", job.ID, status, message)
}

func executionMessage(err error, stderr string) string {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return err.Error()
	}
	return fmt.Sprintf("%v: %s", err, stderr)
}
