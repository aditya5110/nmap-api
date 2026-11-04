//go:build integration

package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"nmap-api/internal/config"
	"nmap-api/internal/domain"
)

func TestPostgresCreateScanRequestWithJobsRollback(t *testing.T) {
	db, repo, ctx := newIntegrationRepository(t)

	_, err := repo.CreateScanRequestWithJobs(
		ctx,
		domain.ScanRequest{
			RequestUUID: "6e0aa93a-4d0a-45ac-8ff0-ace0e1480e2c",
			Status:      "pending",
		},
		[]domain.ScanJob{
			{TargetValue: "8.8.8.8", TargetType: "ip", Status: "pending", TimeoutSeconds: 120},
			{TargetValue: "example.com", TargetType: "hostname", Status: "invalid", TimeoutSeconds: 120},
		},
	)
	if err == nil {
		t.Fatal("expected second job insert to fail due to the status constraint")
	}

	assertCount(t, ctx, db, "scan_requests", 0)
	assertCount(t, ctx, db, "scan_jobs", 0)
}

func TestPostgresSaveScanResultWithPortsRollback(t *testing.T) {
	db, repo, ctx := newIntegrationRepository(t)

	var requestID, jobID int64
	if err := db.QueryRowContext(
		ctx,
		`INSERT INTO scan_requests (request_uuid, status) VALUES ($1, 'pending') RETURNING id`,
		"c13d647a-7b6e-4e31-b0a2-50a598bef04e",
	).Scan(&requestID); err != nil {
		t.Fatalf("insert fixture request: %v", err)
	}
	if err := db.QueryRowContext(
		ctx,
		`INSERT INTO scan_jobs (request_id, target_value, target_type, status) VALUES ($1, 'example.com', 'hostname', 'pending') RETURNING id`,
		requestID,
	).Scan(&jobID); err != nil {
		t.Fatalf("insert fixture job: %v", err)
	}

	now := time.Now().UTC()
	_, err := repo.SaveScanResultWithPorts(ctx, domain.ScanResult{
		JobID:       jobID,
		TargetValue: "example.com",
		HostIP:      "93.184.216.34",
		HostStatus:  "up",
		StartedAt:   now,
		FinishedAt:  now.Add(time.Second),
		RawXML:      "<nmap></nmap>",
	}, []domain.ScanPort{
		{Port: 80, Protocol: "tcp", State: "open"},
		{Port: 80, Protocol: "tcp", State: "open"},
	})
	if err == nil {
		t.Fatal("expected duplicate port insert to fail due to the unique constraint")
	}

	assertCount(t, ctx, db, "scan_results", 0)
	assertCount(t, ctx, db, "scan_ports", 0)
}

func TestPostgresMigrationIndexes(t *testing.T) {
	db, _, ctx := newIntegrationRepository(t)

	checks := []struct {
		table string
		index string
	}{
		{table: "scan_jobs", index: "idx_scan_jobs_request_id"},
		{table: "scan_jobs", index: "idx_scan_jobs_status_created_at"},
		{table: "scan_jobs", index: "idx_scan_jobs_target_value"},
		{table: "scan_results", index: "scan_results_job_id_host_ip_key"},
		{table: "scan_results", index: "idx_scan_results_host_ip_finished_at"},
		{table: "scan_ports", index: "scan_ports_scan_result_id_port_protocol_key"},
	}
	for _, check := range checks {
		var exists bool
		if err := db.QueryRowContext(ctx,
			`SELECT EXISTS (
				SELECT 1 FROM pg_indexes
				WHERE schemaname = current_schema() AND tablename = $1 AND indexname = $2
			)`, check.table, check.index,
		).Scan(&exists); err != nil {
			t.Fatalf("check index %s: %v", check.index, err)
		}
		if !exists {
			t.Errorf("expected index %s on %s", check.index, check.table)
		}
	}

	for _, index := range []string{
		"idx_scan_results_job_id",
		"idx_scan_ports_scan_result_id",
		"idx_scan_ports_port_protocol",
	} {
		var exists bool
		if err := db.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() AND indexname = $1)`, index,
		).Scan(&exists); err != nil {
			t.Fatalf("check removed index %s: %v", index, err)
		}
		if exists {
			t.Errorf("did not expect redundant or unused index %s", index)
		}
	}
}

func TestPostgresConcurrentClaimsSkipLockedJobs(t *testing.T) {
	db, repo, ctx := newIntegrationRepository(t)
	requestID := createIntegrationRequest(t, ctx, db)
	firstID := createIntegrationJob(t, ctx, db, requestID, "192.0.2.1", time.Now().Add(-time.Minute))
	secondID := createIntegrationJob(t, ctx, db, requestID, "192.0.2.2", time.Now())

	lockTx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin lock transaction: %v", err)
	}
	var lockedID int64
	if err := lockTx.QueryRowContext(ctx,
		`SELECT id FROM scan_jobs WHERE status = 'pending' ORDER BY created_at, id LIMIT 1 FOR UPDATE`,
	).Scan(&lockedID); err != nil {
		_ = lockTx.Rollback()
		t.Fatalf("lock oldest pending job: %v", err)
	}
	if lockedID != firstID {
		_ = lockTx.Rollback()
		t.Fatalf("expected to lock first job %d, got %d", firstID, lockedID)
	}

	claimed, err := repo.ClaimNextJob(ctx, 150*time.Second)
	if err != nil {
		_ = lockTx.Rollback()
		t.Fatalf("claim unlocked job: %v", err)
	}
	if claimed == nil || claimed.ID != secondID {
		_ = lockTx.Rollback()
		t.Fatalf("expected SKIP LOCKED to claim job %d, got %#v", secondID, claimed)
	}
	if claimed.Status != "running" || claimed.Attempts != 1 || claimed.StartedAt == nil || claimed.LeaseExpiresAt == nil {
		_ = lockTx.Rollback()
		t.Fatalf("claimed job missing running status/attempt/lease: %#v", claimed)
	}
	if err := lockTx.Rollback(); err != nil {
		t.Fatalf("release row lock: %v", err)
	}

	claimedFirst, err := repo.ClaimNextJob(ctx, 150*time.Second)
	if err != nil || claimedFirst == nil || claimedFirst.ID != firstID {
		t.Fatalf("expected first job %d after releasing lock, got %#v err=%v", firstID, claimedFirst, err)
	}
}

func TestPostgresConcurrentWorkersClaimDifferentJobs(t *testing.T) {
	db, repo, ctx := newIntegrationRepository(t)
	requestID := createIntegrationRequest(t, ctx, db)
	createIntegrationJob(t, ctx, db, requestID, "192.0.2.11", time.Now().Add(-time.Minute))
	createIntegrationJob(t, ctx, db, requestID, "192.0.2.12", time.Now())

	type claimResult struct {
		job *domain.ScanJob
		err error
	}
	start := make(chan struct{})
	results := make(chan claimResult, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			job, err := repo.ClaimNextJob(ctx, 150*time.Second)
			results <- claimResult{job: job, err: err}
		}()
	}
	close(start)

	claimedIDs := make(map[int64]struct{}, 2)
	for i := 0; i < 2; i++ {
		result := <-results
		if result.err != nil {
			t.Fatalf("concurrent claim failed: %v", result.err)
		}
		if result.job == nil {
			t.Fatal("concurrent claimer found no job")
		}
		if _, duplicate := claimedIDs[result.job.ID]; duplicate {
			t.Fatalf("two workers claimed job %d", result.job.ID)
		}
		claimedIDs[result.job.ID] = struct{}{}
	}
	if len(claimedIDs) != 2 {
		t.Fatalf("expected two distinct claimed jobs, got %v", claimedIDs)
	}
}

func TestPostgresExpiredLeaseRetriesThenFailsAndFencesStaleClaim(t *testing.T) {
	db, repo, ctx := newIntegrationRepository(t)
	requestID := createIntegrationRequest(t, ctx, db)
	jobID := createIntegrationJob(t, ctx, db, requestID, "192.0.2.20", time.Now())

	first, err := repo.ClaimNextJob(ctx, 150*time.Second)
	if err != nil || first == nil || first.Attempts != 1 {
		t.Fatalf("first claim failed: job=%#v err=%v", first, err)
	}
	expireIntegrationJob(t, ctx, db, jobID)
	if count, err := repo.RecoverExpiredJobs(ctx); err != nil || count != 1 {
		t.Fatalf("first lease recovery count=%d err=%v", count, err)
	}

	second, err := repo.ClaimNextJob(ctx, 150*time.Second)
	if err != nil || second == nil || second.Attempts != 2 {
		t.Fatalf("second claim failed: job=%#v err=%v", second, err)
	}
	if updated, err := repo.UpdateClaimedJobStatus(ctx, *first, "failed", time.Now().UTC(), strPtr("stale")); err != nil || updated {
		t.Fatalf("stale claim updated current job: updated=%v err=%v", updated, err)
	}
	if err := repo.CompleteJobWithResults(ctx, *first, []domain.ScanResult{{
		JobID: jobID, TargetValue: "192.0.2.20", HostIP: "192.0.2.20", HostStatus: "up",
		StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(), RawXML: "stale",
	}}, [][]domain.ScanPort{{}}); !errors.Is(err, ErrClaimLost) {
		t.Fatalf("expected stale completion to be rejected, got %v", err)
	}

	expireIntegrationJob(t, ctx, db, jobID)
	if count, err := repo.RecoverExpiredJobs(ctx); err != nil || count != 1 {
		t.Fatalf("second lease recovery count=%d err=%v", count, err)
	}
	third, err := repo.ClaimNextJob(ctx, 150*time.Second)
	if err != nil || third == nil || third.Attempts != 3 {
		t.Fatalf("third claim failed: job=%#v err=%v", third, err)
	}
	expireIntegrationJob(t, ctx, db, jobID)
	if count, err := repo.RecoverExpiredJobs(ctx); err != nil || count != 1 {
		t.Fatalf("final lease recovery count=%d err=%v", count, err)
	}

	var status string
	var attempts int
	if err := db.QueryRowContext(ctx, `SELECT status, attempts FROM scan_jobs WHERE id = $1`, jobID).Scan(&status, &attempts); err != nil {
		t.Fatalf("read exhausted job: %v", err)
	}
	if status != "failed" || attempts != MaxJobAttempts {
		t.Fatalf("expected exhausted job failed at %d attempts, got status=%q attempts=%d", MaxJobAttempts, status, attempts)
	}
}

func TestPostgresScanRequestStatusAggregationAndLeaseRecovery(t *testing.T) {
	db, repo, ctx := newIntegrationRepository(t)
	requestID := createIntegrationRequest(t, ctx, db)
	firstID := createIntegrationJob(t, ctx, db, requestID, "192.0.2.41", time.Now().Add(-2*time.Minute))
	createIntegrationJob(t, ctx, db, requestID, "192.0.2.42", time.Now().Add(-time.Minute))
	createIntegrationJob(t, ctx, db, requestID, "192.0.2.43", time.Now())
	assertScanRequestStatus(t, ctx, db, requestID, "pending")

	first, err := repo.ClaimNextJob(ctx, 150*time.Second)
	if err != nil || first == nil || first.ID != firstID {
		t.Fatalf("claim first request job: job=%#v err=%v", first, err)
	}
	assertScanRequestStatus(t, ctx, db, requestID, "running")
	if updated, err := repo.UpdateClaimedJobStatus(ctx, *first, "completed", time.Now().UTC(), nil); err != nil || !updated {
		t.Fatalf("complete first request job: updated=%v err=%v", updated, err)
	}
	assertScanRequestStatus(t, ctx, db, requestID, "running")

	second, err := repo.ClaimNextJob(ctx, 150*time.Second)
	if err != nil || second == nil {
		t.Fatalf("claim second request job: job=%#v err=%v", second, err)
	}
	expireIntegrationJob(t, ctx, db, second.ID)
	if recovered, err := repo.RecoverExpiredJobs(ctx); err != nil || recovered != 1 {
		t.Fatalf("recover request lease: count=%d err=%v", recovered, err)
	}
	assertScanRequestStatus(t, ctx, db, requestID, "running")
	secondRetry, err := repo.ClaimNextJob(ctx, 150*time.Second)
	if err != nil || secondRetry == nil || secondRetry.ID != second.ID || secondRetry.Attempts != 2 {
		t.Fatalf("reclaim recovered request job: job=%#v err=%v", secondRetry, err)
	}
	if updated, err := repo.UpdateClaimedJobStatus(ctx, *secondRetry, "failed", time.Now().UTC(), strPtr("scan failed")); err != nil || !updated {
		t.Fatalf("fail second request job: updated=%v err=%v", updated, err)
	}
	assertScanRequestStatus(t, ctx, db, requestID, "running")

	third, err := repo.ClaimNextJob(ctx, 150*time.Second)
	if err != nil || third == nil {
		t.Fatalf("claim third request job: job=%#v err=%v", third, err)
	}
	if updated, err := repo.UpdateClaimedJobStatus(ctx, *third, "timed_out", time.Now().UTC(), strPtr("timed out")); err != nil || !updated {
		t.Fatalf("time out third request job: updated=%v err=%v", updated, err)
	}
	assertScanRequestStatus(t, ctx, db, requestID, "failed")
}

func TestPostgresLeaseRecoveryRefreshesMultipleRequests(t *testing.T) {
	db, repo, ctx := newIntegrationRepository(t)
	firstRequestID := createIntegrationRequest(t, ctx, db)
	firstJobID := createIntegrationJob(t, ctx, db, firstRequestID, "192.0.2.51", time.Now())
	secondRequestID := createIntegrationRequest(t, ctx, db)
	secondJobID := createIntegrationJob(t, ctx, db, secondRequestID, "192.0.2.52", time.Now())

	for _, wantID := range []int64{firstJobID, secondJobID} {
		job, err := repo.ClaimNextJob(ctx, 150*time.Second)
		if err != nil || job == nil || job.ID != wantID {
			t.Fatalf("claim job %d: job=%#v err=%v", wantID, job, err)
		}
		expireIntegrationJob(t, ctx, db, wantID)
	}
	if recovered, err := repo.RecoverExpiredJobs(ctx); err != nil || recovered != 2 {
		t.Fatalf("recover jobs from multiple requests: count=%d err=%v", recovered, err)
	}
	assertScanRequestStatus(t, ctx, db, firstRequestID, "pending")
	assertScanRequestStatus(t, ctx, db, secondRequestID, "pending")
}

func TestPostgresScanRequestTerminalAggregateStatuses(t *testing.T) {
	db, repo, ctx := newIntegrationRepository(t)

	timedOutRequestID := createIntegrationRequest(t, ctx, db)
	createIntegrationJob(t, ctx, db, timedOutRequestID, "192.0.2.61", time.Now())
	createIntegrationJob(t, ctx, db, timedOutRequestID, "192.0.2.62", time.Now().Add(time.Second))
	for index, status := range []string{"timed_out", "completed"} {
		job, err := repo.ClaimNextJob(ctx, 150*time.Second)
		if err != nil || job == nil {
			t.Fatalf("claim terminal job %d: job=%#v err=%v", index, job, err)
		}
		if updated, err := repo.UpdateClaimedJobStatus(ctx, *job, status, time.Now().UTC(), nil); err != nil || !updated {
			t.Fatalf("update terminal job to %s: updated=%v err=%v", status, updated, err)
		}
	}
	assertScanRequestStatus(t, ctx, db, timedOutRequestID, "timed_out")

	completedRequestID := createIntegrationRequest(t, ctx, db)
	createIntegrationJob(t, ctx, db, completedRequestID, "192.0.2.63", time.Now())
	job, err := repo.ClaimNextJob(ctx, 150*time.Second)
	if err != nil || job == nil {
		t.Fatalf("claim all-completed job: job=%#v err=%v", job, err)
	}
	if updated, err := repo.UpdateClaimedJobStatus(ctx, *job, "completed", time.Now().UTC(), nil); err != nil || !updated {
		t.Fatalf("complete all-completed job: updated=%v err=%v", updated, err)
	}
	assertScanRequestStatus(t, ctx, db, completedRequestID, "completed")
}

func TestPostgresCompletionReplacesResultsWithoutDuplicates(t *testing.T) {
	db, repo, ctx := newIntegrationRepository(t)
	requestID := createIntegrationRequest(t, ctx, db)
	jobID := createIntegrationJob(t, ctx, db, requestID, "example.test", time.Now())
	first, err := repo.ClaimNextJob(ctx, 150*time.Second)
	if err != nil || first == nil {
		t.Fatalf("claim first attempt: job=%#v err=%v", first, err)
	}

	started := time.Now().UTC()
	firstResult := domain.ScanResult{JobID: jobID, TargetValue: "example.test", HostIP: "192.0.2.30", HostStatus: "up", StartedAt: started, FinishedAt: started.Add(time.Second), RawXML: "first"}
	if err := repo.CompleteJobWithResults(ctx, *first, []domain.ScanResult{firstResult}, [][]domain.ScanPort{{{Port: 80, Protocol: "tcp", State: "open"}}}); err != nil {
		t.Fatalf("complete first attempt: %v", err)
	}

	if _, err := db.ExecContext(ctx, `UPDATE scan_jobs SET status = 'pending', started_at = NULL, finished_at = NULL, lease_expires_at = NULL WHERE id = $1`, jobID); err != nil {
		t.Fatalf("prepare retry fixture: %v", err)
	}
	second, err := repo.ClaimNextJob(ctx, 150*time.Second)
	if err != nil || second == nil || second.Attempts != 2 {
		t.Fatalf("claim retry: job=%#v err=%v", second, err)
	}
	secondResult := firstResult
	secondResult.RawXML = "second"
	secondResult.FinishedAt = started.Add(2 * time.Second)
	if err := repo.CompleteJobWithResults(ctx, *second, []domain.ScanResult{secondResult}, [][]domain.ScanPort{{{Port: 443, Protocol: "tcp", State: "filtered"}}}); err != nil {
		t.Fatalf("complete retry: %v", err)
	}

	assertCount(t, ctx, db, "scan_results", 1)
	assertCount(t, ctx, db, "scan_ports", 1)
	var state, rawXML string
	if err := db.QueryRowContext(ctx, `SELECT p.state, r.raw_xml FROM scan_ports p JOIN scan_results r ON r.id = p.scan_result_id`).Scan(&state, &rawXML); err != nil {
		t.Fatalf("read replaced result: %v", err)
	}
	if state != "filtered" || rawXML != "second" {
		t.Fatalf("expected retry result to replace prior output, state=%q xml=%q", state, rawXML)
	}
}

func newIntegrationRepository(t *testing.T) (*sql.DB, *Repository, context.Context) {
	t.Helper()

	cfg, err := integrationDBConfig()
	if err != nil {
		t.Fatalf("invalid PostgreSQL integration configuration: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	db, err := OpenDB(ctx, cfg)
	if err != nil {
		cancel()
		t.Fatalf("PostgreSQL integration database unavailable or misconfigured at %s:%d/%s: %v; start/configure PostgreSQL with DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, and DB_NAME", cfg.DBHost, cfg.DBPort, cfg.DBName, err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)

	schemaBytes := make([]byte, 8)
	if _, err := rand.Read(schemaBytes); err != nil {
		_ = db.Close()
		cancel()
		t.Fatalf("create integration schema name: %v", err)
	}
	schema := "nmap_api_integration_" + hex.EncodeToString(schemaBytes)
	if _, err := db.ExecContext(ctx, `CREATE SCHEMA "`+schema+`"`); err != nil {
		_ = db.Close()
		cancel()
		t.Fatalf("create isolated PostgreSQL integration schema: %v", err)
	}

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if _, err := db.ExecContext(cleanupCtx, `DROP SCHEMA "`+schema+`" CASCADE`); err != nil {
			t.Errorf("drop isolated integration schema: %v", err)
		}
		if err := db.Close(); err != nil {
			t.Errorf("close integration database: %v", err)
		}
		cancel()
	})

	connections := make([]*sql.Conn, 0, 4)
	for i := 0; i < cap(connections); i++ {
		connection, err := db.Conn(ctx)
		if err != nil {
			t.Fatalf("open integration DB connection: %v", err)
		}
		connections = append(connections, connection)
	}
	for _, connection := range connections {
		if _, err := connection.ExecContext(ctx, `SET search_path TO "`+schema+`"`); err != nil {
			t.Fatalf("set isolated PostgreSQL integration schema: %v", err)
		}
	}
	for _, connection := range connections {
		if err := connection.Close(); err != nil {
			t.Fatalf("release integration DB connection: %v", err)
		}
	}
	if err := applyInitialMigration(ctx, db); err != nil {
		t.Fatalf("apply initial PostgreSQL migration: %v", err)
	}

	return db, NewRepository(db), ctx
}

func createIntegrationRequest(t *testing.T, ctx context.Context, db *sql.DB) int64 {
	t.Helper()
	requestUUIDBytes := make([]byte, 16)
	if _, err := rand.Read(requestUUIDBytes); err != nil {
		t.Fatalf("generate integration request UUID: %v", err)
	}
	requestUUID := fmt.Sprintf("%x-%x-%x-%x-%x", requestUUIDBytes[0:4], requestUUIDBytes[4:6], requestUUIDBytes[6:8], requestUUIDBytes[8:10], requestUUIDBytes[10:16])
	var requestID int64
	if err := db.QueryRowContext(ctx,
		`INSERT INTO scan_requests (request_uuid, status) VALUES ($1, 'pending') RETURNING id`,
		requestUUID,
	).Scan(&requestID); err != nil {
		t.Fatalf("insert integration request: %v", err)
	}
	return requestID
}

func assertScanRequestStatus(t *testing.T, ctx context.Context, db *sql.DB, requestID int64, want string) {
	t.Helper()
	var got string
	if err := db.QueryRowContext(ctx, `SELECT status FROM scan_requests WHERE id = $1`, requestID).Scan(&got); err != nil {
		t.Fatalf("read scan request %d status: %v", requestID, err)
	}
	if got != want {
		t.Fatalf("scan request %d status = %q, want %q", requestID, got, want)
	}
}

func createIntegrationJob(t *testing.T, ctx context.Context, db *sql.DB, requestID int64, target string, createdAt time.Time) int64 {
	t.Helper()
	var jobID int64
	if err := db.QueryRowContext(ctx,
		`INSERT INTO scan_jobs (request_id, target_value, target_type, status, created_at)
		 VALUES ($1, $2, 'hostname', 'pending', $3) RETURNING id`, requestID, target, createdAt,
	).Scan(&jobID); err != nil {
		t.Fatalf("insert integration job: %v", err)
	}
	return jobID
}

func expireIntegrationJob(t *testing.T, ctx context.Context, db *sql.DB, jobID int64) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `UPDATE scan_jobs SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1`, jobID); err != nil {
		t.Fatalf("expire integration job lease: %v", err)
	}
}

func integrationDBConfig() (config.Config, error) {
	password := os.Getenv("DB_PASSWORD")
	if password == "" {
		return config.Config{}, fmt.Errorf("DB_PASSWORD must be set for PostgreSQL integration tests")
	}

	port, err := strconv.Atoi(envOrDefault("DB_PORT", "5432"))
	if err != nil {
		return config.Config{}, fmt.Errorf("DB_PORT must be an integer: %w", err)
	}
	return config.Config{
		DBHost:     envOrDefault("DB_HOST", "localhost"),
		DBPort:     port,
		DBUser:     envOrDefault("DB_USER", "appuser"),
		DBPassword: password,
		DBName:     envOrDefault("DB_NAME", "nmapdb"),
		DBSSLMode:  envOrDefault("DB_SSLMODE", "disable"),
	}, nil
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func applyInitialMigration(ctx context.Context, db *sql.DB) error {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		return fmt.Errorf("locate integration test source file")
	}
	migrationPath := filepath.Join(filepath.Dir(currentFile), "..", "..", "migrations", "001_init.up.sql")
	migration, err := os.ReadFile(migrationPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", migrationPath, err)
	}

	for _, statement := range strings.Split(string(migration), ";") {
		statement = strings.TrimSpace(statement)
		if statement == "" {
			continue
		}
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("execute migration statement %q: %w", statement, err)
		}
	}
	return nil
}

func assertCount(t *testing.T, ctx context.Context, db *sql.DB, table string, want int) {
	t.Helper()
	var got int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table).Scan(&got); err != nil {
		t.Fatalf("count rows in %s: %v", table, err)
	}
	if got != want {
		t.Errorf("expected %d rows in %s after rollback, got %d", want, table, got)
	}
}
