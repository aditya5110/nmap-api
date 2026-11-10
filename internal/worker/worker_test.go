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

// TestProcessorSuccessfulScan verifies fake Nmap XML marks the job completed and stores its resolved host and open HTTP port.
func TestProcessorSuccessfulScan(t *testing.T) {
	repo := newTestRepository(testJob(1, "example.test", 60))
	metrics := newRecordingMetrics()
	processor := newTestProcessorWithMetrics(t, repo, "printf '%s' "+shellQuote(validScanXML)+"\n", 60*time.Second, metrics)
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
	if got := metrics.outcomeCount("completed"); got != 1 || metrics.totalOutcomes() != 1 {
		t.Fatalf("persisted completion metrics = completed:%d total:%d, want 1 and 1", got, metrics.totalOutcomes())
	}
	if metrics.nmapDurationCount() != 1 || metrics.lastNmapDuration() <= 0 {
		t.Fatalf("Nmap duration observations = %d, last duration %s", metrics.nmapDurationCount(), metrics.lastNmapDuration())
	}
}

// TestProcessorPersistsExpandedExtraports verifies an aggregate filtered observation reaches the repository with its port, state, and reason intact.
func TestProcessorPersistsExpandedExtraports(t *testing.T) {
	xmlData, err := os.ReadFile(filepath.Join("..", "nmap", "testdata", "extraports.xml"))
	if err != nil {
		t.Fatalf("read aggregate XML fixture: %v", err)
	}
	repo := newTestRepository(testJob(10, "aggregate.example", 60))
	processor := newTestProcessor(t, repo, "printf '%s' "+shellQuote(string(xmlData))+"\n", 60*time.Second)
	job := claimJob(t, repo)

	if err := processor.process(context.Background(), job); err != nil {
		t.Fatalf("process aggregate scan: %v", err)
	}

	for _, port := range repo.ports[0] {
		if port.Port == 8080 {
			if port.Protocol != "tcp" || port.State != "filtered" || port.Reason == nil || *port.Reason != "no-response" {
				t.Fatalf("unexpected persisted observation for port 8080: %#v", port)
			}
			return
		}
	}
	t.Fatal("expected aggregate XML port 8080 to reach the repository")
}

// TestProcessorNmapFailureIsFailed verifies a fake Nmap exit failure marks the job failed and preserves stderr in its error details.
func TestProcessorNmapFailureIsFailed(t *testing.T) {
	repo := newTestRepository(testJob(2, "example.test", 60))
	metrics := newRecordingMetrics()
	processor := newTestProcessorWithMetrics(t, repo, "printf 'connection failed' >&2\nexit 7\n", 60*time.Second, metrics)
	job := claimJob(t, repo)

	err := processor.process(context.Background(), job)
	if err == nil || !strings.Contains(err.Error(), "connection failed") {
		t.Fatalf("expected useful Nmap failure, got %v", err)
	}
	stored := repo.jobSnapshot(job.ID)
	if stored.Status != "failed" || stored.ErrorMessage == nil || !strings.Contains(*stored.ErrorMessage, "connection failed") {
		t.Fatalf("expected failed status and diagnostic, got %#v", stored)
	}
	if got := metrics.outcomeCount("failed"); got != 1 || metrics.totalOutcomes() != 1 {
		t.Fatalf("persisted failure metrics = failed:%d total:%d, want 1 and 1", got, metrics.totalOutcomes())
	}
}

// TestProcessorNmapTimeoutIsTimedOut verifies a fake scan exceeding its one-second limit leaves the job timed_out.
func TestProcessorNmapTimeoutIsTimedOut(t *testing.T) {
	repo := newTestRepository(testJob(3, "example.test", 1))
	metrics := newRecordingMetrics()
	processor := newTestProcessorWithMetrics(t, repo, "exec /bin/sleep 5\n", time.Second, metrics)
	job := claimJob(t, repo)

	err := processor.process(context.Background(), job)
	if err == nil || !strings.Contains(err.Error(), "timed_out") {
		t.Fatalf("expected timeout status error, got %v", err)
	}
	if status := repo.jobSnapshot(job.ID).Status; status != "timed_out" {
		t.Fatalf("expected timed_out job status, got %q", status)
	}
	if got := metrics.outcomeCount("timed_out"); got != 1 || metrics.totalOutcomes() != 1 {
		t.Fatalf("timeout metrics = timed_out:%d total:%d, want 1 and 1", got, metrics.totalOutcomes())
	}
}

// TestProcessorXMLParsingFailureIsFailed verifies a successful process with a non-Nmap XML document fails the job without results.
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

// TestProcessorPersistenceFailureMarksJobFailed verifies a simulated database write error marks the claimed job failed.
func TestProcessorPersistenceFailureMarksJobFailed(t *testing.T) {
	repo := newTestRepository(testJob(5, "example.test", 60))
	repo.completeErr = errors.New("database unavailable")
	metrics := newRecordingMetrics()
	processor := newTestProcessorWithMetrics(t, repo, "printf '%s' "+shellQuote(validScanXML)+"\n", 60*time.Second, metrics)
	job := claimJob(t, repo)

	if err := processor.process(context.Background(), job); err == nil || !strings.Contains(err.Error(), "database unavailable") {
		t.Fatalf("expected persistence failure, got %v", err)
	}
	if status := repo.jobSnapshot(job.ID).Status; status != "failed" {
		t.Fatalf("expected failed status after persistence error, got %q", status)
	}
	if metrics.outcomeCount("failed") != 1 || metrics.outcomeCount("completed") != 0 {
		t.Fatalf("unexpected terminal outcome metrics: %#v", metrics.outcomes)
	}
}

// TestProcessorLostClaimDoesNotRecordTerminalOutcome verifies a stale worker that cannot persist completion does not increment a terminal job counter.
func TestProcessorLostClaimDoesNotRecordTerminalOutcome(t *testing.T) {
	repo := newTestRepository(testJob(11, "example.test", 60))
	repo.completeErr = db.ErrClaimLost
	metrics := newRecordingMetrics()
	processor := newTestProcessorWithMetrics(t, repo, "printf '%s' "+shellQuote(validScanXML)+"\n", 60*time.Second, metrics)
	job := claimJob(t, repo)

	if err := processor.process(context.Background(), job); !errors.Is(err, db.ErrClaimLost) {
		t.Fatalf("expected lost claim, got %v", err)
	}
	if metrics.totalOutcomes() != 0 {
		t.Fatalf("lost claim recorded terminal outcomes: %#v", metrics.outcomes)
	}
}

// TestProcessorUsesJobTimeoutAndCapsAtMVPMaximum verifies an oversized job timeout passed to the runner is capped at 120 seconds.
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

// TestProcessorShutdownCancellationLeavesClaimRecoverable verifies canceling a worker during a fake scan leaves its running job leased without marking it failed.
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

// TestPoolContinuesAfterOrdinaryJobFailure verifies one fake Nmap failure is recorded while the same worker completes the next job.
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

// TestPoolCoordinatesPeriodicLeaseRecovery verifies the pool's single recovery loop makes repeated recovery calls until canceled.
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

// TestPoolCountsOnlyPermanentlyFailedLeaseRecoveries verifies retryable expired jobs are requeued without failure metrics and exhausted jobs count once.
func TestPoolCountsOnlyPermanentlyFailedLeaseRecoveries(t *testing.T) {
	now := time.Now().UTC()
	started := now.Add(-time.Minute)
	expired := now.Add(-time.Second)
	repo := newTestRepository(
		domain.ScanJob{ID: 30, Status: "running", Attempts: 1, StartedAt: &started, LeaseExpiresAt: &expired},
		domain.ScanJob{ID: 31, Status: "running", Attempts: db.MaxJobAttempts, StartedAt: &started, LeaseExpiresAt: &expired},
	)
	metrics := newRecordingMetrics()
	processor, err := NewProcessorWithMetrics(repo, &recordingRunner{}, time.Minute, metrics)
	if err != nil {
		t.Fatalf("NewProcessorWithMetrics: %v", err)
	}
	pool, err := NewPool(processor, 1, time.Millisecond)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	pool.recoveryInterval = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pool.runRecovery(ctx)
		close(done)
	}()

	deadline := time.After(time.Second)
	for repo.recoveryCallCount() == 0 {
		select {
		case <-time.After(time.Millisecond):
		case <-deadline:
			cancel()
			<-done
			t.Fatal("recovery loop did not run")
		}
	}
	cancel()
	<-done

	if got := repo.jobSnapshot(30).Status; got != "pending" {
		t.Fatalf("retryable expired job status = %q, want pending", got)
	}
	if got := repo.jobSnapshot(31).Status; got != "failed" {
		t.Fatalf("exhausted expired job status = %q, want failed", got)
	}
	if metrics.outcomeCount("failed") != 1 || metrics.totalOutcomes() != 1 {
		t.Fatalf("recovery outcome metrics = %#v, want exactly one permanent failure", metrics.outcomes)
	}
}

// TestNewPoolRequiresPositiveWorkerCount verifies pool construction rejects zero workers instead of starting no scan processors.
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
	return newTestProcessorWithMetrics(t, repo, script, defaultTimeout, nil)
}

func newTestProcessorWithMetrics(t *testing.T, repo *testRepository, script string, defaultTimeout time.Duration, metrics MetricsRecorder) *Processor {
	t.Helper()
	runner := newTestRunner(t, script, defaultTimeout)
	processor, err := NewProcessorWithMetrics(repo, runner, defaultTimeout, metrics)
	if err != nil {
		t.Fatalf("NewProcessor: %v", err)
	}
	return processor
}

type recordingMetrics struct {
	mu            sync.Mutex
	outcomes      map[string]int64
	nmapDurations []time.Duration
}

func newRecordingMetrics() *recordingMetrics {
	return &recordingMetrics{outcomes: make(map[string]int64)}
}

func (m *recordingMetrics) RecordNmapExecution(duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nmapDurations = append(m.nmapDurations, duration)
}

func (m *recordingMetrics) RecordScanJobOutcomes(outcome string, count int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.outcomes[outcome] += count
}

func (m *recordingMetrics) outcomeCount(outcome string) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.outcomes[outcome]
}

func (m *recordingMetrics) totalOutcomes() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	var total int64
	for _, count := range m.outcomes {
		total += count
	}
	return total
}

func (m *recordingMetrics) nmapDurationCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.nmapDurations)
}

func (m *recordingMetrics) lastNmapDuration() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.nmapDurations) == 0 {
		return 0
	}
	return m.nmapDurations[len(m.nmapDurations)-1]
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

func (r *testRepository) RecoverExpiredJobs(_ context.Context) (db.LeaseRecoveryResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recoverCalls++
	var recovered db.LeaseRecoveryResult
	for id, job := range r.jobs {
		if job.Status != "running" || job.LeaseExpiresAt == nil || job.LeaseExpiresAt.After(time.Now()) {
			continue
		}
		if job.Attempts >= db.MaxJobAttempts {
			job.Status = "failed"
			recovered.Failed++
		} else {
			job.Status = "pending"
			recovered.Requeued++
		}
		job.LeaseExpiresAt = nil
		r.jobs[id] = job
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
