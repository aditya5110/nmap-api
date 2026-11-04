package worker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"nmap-api/internal/db"
	"nmap-api/internal/domain"
	"nmap-api/internal/nmap"
)

const validScanXML = `<nmaprun start="1700000000"><host starttime="1700000000" endtime="1700000002"><status state="up"/><address addr="192.0.2.50" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http"/></port></ports></host><runstats><finished time="1700000002"/></runstats></nmaprun>`

func TestProcessorSuccessfulScan(t *testing.T) {
	repo := newTestRepository(testJob(1, "example.test", 60))
	processor := newTestProcessor(t, repo, "printf '%s' "+shellQuote(validScanXML)+"\n", 60*time.Second)
	job := claimJob(t, repo)

	if err := processor.process(context.Background(), job); err != nil {
		t.Fatalf("process successful scan: %v", err)
	}

	stored := repo.jobSnapshot(job.ID)
	if stored.Status != "completed" {
		t.Fatalf("expected completed status, got %q", stored.Status)
	}
	if len(repo.results) != 1 || len(repo.ports) != 1 || len(repo.ports[0]) != 1 {
		t.Fatalf("unexpected persisted results: results=%#v ports=%#v", repo.results, repo.ports)
	}
	if repo.results[0].HostIP != "192.0.2.50" || repo.results[0].HostStatus != "up" {
		t.Fatalf("unexpected persisted host: %#v", repo.results[0])
	}
	if repo.ports[0][0].Port != 80 || repo.ports[0][0].State != "open" || *repo.ports[0][0].ServiceName != "http" {
		t.Fatalf("unexpected persisted port: %#v", repo.ports[0][0])
	}
}

func TestProcessorNmapFailureIsFailed(t *testing.T) {
	repo := newTestRepository(testJob(2, "example.test", 60))
	processor := newTestProcessor(t, repo, "printf 'connection failed' >&2\nexit 7\n", 60*time.Second)
	job := claimJob(t, repo)

	err := processor.process(context.Background(), job)
	if err == nil || !strings.Contains(err.Error(), "connection failed") {
		t.Fatalf("expected useful Nmap failure, got %v", err)
	}
	stored := repo.jobSnapshot(job.ID)
	if stored.Status != "failed" || stored.ErrorMessage == nil || !strings.Contains(*stored.ErrorMessage, "connection failed") {
		t.Fatalf("expected failed status and diagnostic, got %#v", stored)
	}
}

func TestProcessorNmapTimeoutIsTimedOut(t *testing.T) {
	repo := newTestRepository(testJob(3, "example.test", 1))
	processor := newTestProcessor(t, repo, "exec /bin/sleep 5\n", time.Second)
	job := claimJob(t, repo)

	err := processor.process(context.Background(), job)
	if err == nil || !strings.Contains(err.Error(), "timed_out") {
		t.Fatalf("expected timeout status error, got %v", err)
	}
	if status := repo.jobSnapshot(job.ID).Status; status != "timed_out" {
		t.Fatalf("expected timed_out job status, got %q", status)
	}
}

func TestProcessorXMLParsingFailureIsFailed(t *testing.T) {
	repo := newTestRepository(testJob(4, "example.test", 60))
	processor := newTestProcessor(t, repo, "printf '%s' '<not-nmap/>\n'\n", 60*time.Second)
	job := claimJob(t, repo)

	if err := processor.process(context.Background(), job); err == nil || !strings.Contains(err.Error(), "parse Nmap XML") {
		t.Fatalf("expected XML parse failure, got %v", err)
	}
	if status := repo.jobSnapshot(job.ID).Status; status != "failed" {
		t.Fatalf("expected failed status after XML parse failure, got %q", status)
	}
	if len(repo.results) != 0 {
		t.Fatalf("did not expect results after parse failure: %#v", repo.results)
	}
}

func TestProcessorPersistenceFailureMarksJobFailed(t *testing.T) {
	repo := newTestRepository(testJob(5, "example.test", 60))
	repo.completeErr = errors.New("database unavailable")
	processor := newTestProcessor(t, repo, "printf '%s' "+shellQuote(validScanXML)+"\n", 60*time.Second)
	job := claimJob(t, repo)

	if err := processor.process(context.Background(), job); err == nil || !strings.Contains(err.Error(), "database unavailable") {
		t.Fatalf("expected persistence failure, got %v", err)
	}
	if status := repo.jobSnapshot(job.ID).Status; status != "failed" {
		t.Fatalf("expected failed status after persistence error, got %q", status)
	}
}

func TestProcessorUsesJobTimeoutAndCapsAtMVPMaximum(t *testing.T) {
	repo := newTestRepository(testJob(6, "example.test", 999))
	runner := &recordingRunner{output: nmap.RunOutput{XML: []byte(validScanXML)}}
	processor, err := NewProcessor(repo, runner, 90*time.Second)
	if err != nil {
		t.Fatalf("NewProcessor: %v", err)
	}
	job := claimJob(t, repo)

	if err := processor.process(context.Background(), job); err != nil {
		t.Fatalf("process scan: %v", err)
	}
	if runner.timeout != MaxScanTimeout {
		t.Fatalf("expected timeout capped at %s, got %s", MaxScanTimeout, runner.timeout)
	}
}

func TestProcessorShutdownCancellationLeavesClaimRecoverable(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "started")
	repo := newTestRepository(testJob(7, "example.test", 120))
	processor := newTestProcessor(t, repo, ": > "+shellQuote(marker)+"\nexec /bin/sleep 5\n", MaxScanTimeout)
	pool, err := NewPool(processor, 1, time.Millisecond)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- pool.Run(ctx) }()

	waitForFile(t, marker)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("pool shutdown returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("worker pool did not exit after cancellation")
	}

	stored := repo.jobSnapshot(7)
	if stored.Status != "running" || stored.LeaseExpiresAt == nil {
		t.Fatalf("shutdown should leave the job leased for recovery, got %#v", stored)
	}
	if repo.statusUpdateCalls != 0 {
		t.Fatalf("shutdown cancellation should not mark job failed, status updates=%d", repo.statusUpdateCalls)
	}
}

func TestPoolContinuesAfterOrdinaryJobFailure(t *testing.T) {
	repo := newTestRepository(
		testJob(8, "bad.example", 60),
		testJob(9, "good.example", 60),
	)
	script := "if [ \"$8\" = 'bad.example' ]; then printf 'failed' >&2; exit 1; fi\nprintf '%s' " + shellQuote(validScanXML) + "\n"
	runner := newTestRunner(t, script, time.Minute)
	processor, err := NewProcessor(repo, runner, 60*time.Second)
	if err != nil {
		t.Fatalf("NewProcessor: %v", err)
	}
	pool, err := NewPool(processor, 1, time.Millisecond)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- pool.Run(ctx) }()

	deadline := time.After(3 * time.Second)
	for {
		if repo.jobSnapshot(8).Status == "failed" && repo.jobSnapshot(9).Status == "completed" {
			break
		}
		select {
		case <-time.After(5 * time.Millisecond):
		case <-deadline:
			cancel()
			t.Fatal("pool did not process both independent jobs")
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("pool shutdown returned error: %v", err)
	}
}

func TestPoolCoordinatesPeriodicLeaseRecovery(t *testing.T) {
	repo := newTestRepository()
	processor, err := NewProcessor(repo, &recordingRunner{}, time.Minute)
	if err != nil {
		t.Fatalf("NewProcessor: %v", err)
	}
	pool, err := NewPool(processor, 4, time.Millisecond)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	pool.recoveryInterval = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- pool.Run(ctx) }()

	deadline := time.After(time.Second)
	for repo.recoveryCallCount() < 2 {
		select {
		case <-time.After(time.Millisecond):
		case <-deadline:
			cancel()
			t.Fatal("single recovery loop did not run periodically")
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("pool shutdown returned error: %v", err)
	}
	if calls := repo.recoveryCallCount(); calls < 2 || calls > 4 {
		t.Fatalf("expected a small periodic recovery count from one loop, got %d calls", calls)
	}
}

func TestNewPoolRequiresPositiveWorkerCount(t *testing.T) {
	repo := newTestRepository()
	processor, err := NewProcessor(repo, &recordingRunner{}, time.Minute)
	if err != nil {
		t.Fatalf("NewProcessor: %v", err)
	}
	if _, err := NewPool(processor, 0, time.Second); err == nil {
		t.Fatal("expected zero worker count to be rejected")
	}
}

type recordingRunner struct {
	output  nmap.RunOutput
	err     error
	timeout time.Duration
}

func (r *recordingRunner) RunWithTimeout(_ context.Context, _ string, timeout time.Duration) (nmap.RunOutput, error) {
	r.timeout = timeout
	return r.output, r.err
}

func newTestProcessor(t *testing.T, repo *testRepository, script string, defaultTimeout time.Duration) *Processor {
	t.Helper()
	runner := newTestRunner(t, script, defaultTimeout)
	processor, err := NewProcessor(repo, runner, defaultTimeout)
	if err != nil {
		t.Fatalf("NewProcessor: %v", err)
	}
	return processor
}

func newTestRunner(t *testing.T, script string, timeout time.Duration) *nmap.Runner {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "fake-nmap")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nset -eu\n"+script), 0o700); err != nil {
		t.Fatalf("write fake Nmap executable: %v", err)
	}
	runner, err := nmap.NewRunner(binary, timeout)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	return runner
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		select {
		case <-ticker.C:
		case <-timer.C:
			t.Fatal("fake Nmap executable did not start")
		}
	}
}

func testJob(id int64, target string, timeout int) domain.ScanJob {
	return domain.ScanJob{ID: id, TargetValue: target, TargetType: "hostname", Status: "pending", TimeoutSeconds: timeout}
}

func claimJob(t *testing.T, repo *testRepository) domain.ScanJob {
	t.Helper()
	job, err := repo.ClaimNextJob(context.Background(), LeaseDuration)
	if err != nil || job == nil {
		t.Fatalf("claim test job: job=%#v err=%v", job, err)
	}
	return *job
}

type testRepository struct {
	mu                sync.Mutex
	jobs              map[int64]domain.ScanJob
	order             []int64
	results           []domain.ScanResult
	ports             [][]domain.ScanPort
	completeErr       error
	statusUpdateCalls int
	recoverCalls      int
}

func newTestRepository(jobs ...domain.ScanJob) *testRepository {
	repo := &testRepository{jobs: make(map[int64]domain.ScanJob, len(jobs))}
	for _, job := range jobs {
		repo.jobs[job.ID] = job
		repo.order = append(repo.order, job.ID)
	}
	return repo
}

func (r *testRepository) ClaimNextJob(_ context.Context, leaseDuration time.Duration) (*domain.ScanJob, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range r.order {
		job := r.jobs[id]
		if job.Status != "pending" {
			continue
		}
		now := time.Now().UTC()
		job.Status = "running"
		job.Attempts++
		job.StartedAt = &now
		lease := now.Add(leaseDuration)
		job.LeaseExpiresAt = &lease
		r.jobs[id] = job
		return &job, nil
	}
	return nil, nil
}

func (r *testRepository) RecoverExpiredJobs(_ context.Context) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recoverCalls++
	var recovered int64
	for id, job := range r.jobs {
		if job.Status != "running" || job.LeaseExpiresAt == nil || job.LeaseExpiresAt.After(time.Now()) {
			continue
		}
		if job.Attempts >= db.MaxJobAttempts {
			job.Status = "failed"
		} else {
			job.Status = "pending"
		}
		job.LeaseExpiresAt = nil
		r.jobs[id] = job
		recovered++
	}
	return recovered, nil
}

func (r *testRepository) recoveryCallCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.recoverCalls
}

func (r *testRepository) UpdateClaimedJobStatus(_ context.Context, claim domain.ScanJob, status string, finishedAt time.Time, message *string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.statusUpdateCalls++
	job, ok := r.jobs[claim.ID]
	if !ok || !sameClaim(job, claim) {
		return false, nil
	}
	job.Status = status
	job.FinishedAt = &finishedAt
	job.ErrorMessage = message
	job.LeaseExpiresAt = nil
	r.jobs[claim.ID] = job
	return true, nil
}

func (r *testRepository) CompleteJobWithResults(_ context.Context, claim domain.ScanJob, results []domain.ScanResult, ports [][]domain.ScanPort) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.completeErr != nil {
		return r.completeErr
	}
	job, ok := r.jobs[claim.ID]
	if !ok || !sameClaim(job, claim) {
		return db.ErrClaimLost
	}
	job.Status = "completed"
	job.LeaseExpiresAt = nil
	now := time.Now().UTC()
	job.FinishedAt = &now
	r.jobs[claim.ID] = job
	r.results = append([]domain.ScanResult(nil), results...)
	r.ports = make([][]domain.ScanPort, len(ports))
	for i := range ports {
		r.ports[i] = append([]domain.ScanPort(nil), ports[i]...)
	}
	return nil
}

func (r *testRepository) jobSnapshot(id int64) domain.ScanJob {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.jobs[id]
}

func sameClaim(current, claim domain.ScanJob) bool {
	return current.Status == "running" && current.StartedAt != nil && claim.StartedAt != nil &&
		current.LeaseExpiresAt != nil && claim.LeaseExpiresAt != nil &&
		current.StartedAt.Equal(*claim.StartedAt) && current.LeaseExpiresAt.Equal(*claim.LeaseExpiresAt)
}
