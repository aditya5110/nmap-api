package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"nmap-api/internal/domain"
)

type Repository struct {
	db *sql.DB
}

var ErrClaimLost = errors.New("scan job claim is no longer current")

const MaxJobAttempts = 3

type LeaseRecoveryResult struct {
	Requeued int64
	Failed   int64
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) ClaimNextJob(ctx context.Context, leaseDuration time.Duration) (*domain.ScanJob, error) {
	if leaseDuration <= 0 {
		return nil, errors.New("lease duration must be greater than zero")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin job claim transaction: %w", err)
	}
	defer tx.Rollback()

	var id int64
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM scan_jobs
		 WHERE status = 'pending'
		 ORDER BY created_at, id
		 LIMIT 1
		 FOR UPDATE SKIP LOCKED`,
	).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("select pending job: %w", err)
	}

	job, err := scanJob(tx.QueryRowContext(ctx,
		`UPDATE scan_jobs
		 SET status = 'running', started_at = NOW(), finished_at = NULL,
		     attempts = attempts + 1, error_message = NULL,
		     lease_expires_at = NOW() + ($1 * INTERVAL '1 millisecond'), updated_at = NOW()
		 WHERE id = $2 AND status = 'pending'
		 RETURNING id, request_id, target_value, target_type, status, created_at, updated_at,
		           started_at, finished_at, timeout_seconds, attempts, error_message, lease_expires_at`,
		leaseDuration.Milliseconds(), id,
	))
	if err != nil {
		return nil, fmt.Errorf("mark claimed job running: %w", err)
	}
	if err := refreshScanRequestStatus(ctx, tx, job.RequestID); err != nil {
		return nil, fmt.Errorf("update scan request status after claim: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit job claim: %w", err)
	}
	return &job, nil
}

func (r *Repository) RecoverExpiredJobs(ctx context.Context) (LeaseRecoveryResult, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return LeaseRecoveryResult{}, fmt.Errorf("begin lease recovery transaction: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx,
		`UPDATE scan_jobs
		 SET status = CASE WHEN attempts >= $1 THEN 'failed' ELSE 'pending' END,
		     updated_at = NOW(), finished_at = CASE WHEN attempts >= $1 THEN NOW() ELSE NULL END,
		     error_message = CASE WHEN attempts >= $1 THEN 'lease expired after maximum attempts' ELSE NULL END,
		     lease_expires_at = NULL
		 WHERE status = 'running' AND lease_expires_at <= NOW()
		 RETURNING request_id, status`,
		MaxJobAttempts,
	)
	if err != nil {
		return LeaseRecoveryResult{}, fmt.Errorf("recover expired jobs: %w", err)
	}
	requestIDs := make(map[int64]struct{})
	var result LeaseRecoveryResult
	for rows.Next() {
		var requestID int64
		var status string
		if err := rows.Scan(&requestID, &status); err != nil {
			_ = rows.Close()
			return LeaseRecoveryResult{}, fmt.Errorf("read recovered job status: %w", err)
		}
		requestIDs[requestID] = struct{}{}
		if status == "failed" {
			result.Failed++
		} else {
			result.Requeued++
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return LeaseRecoveryResult{}, fmt.Errorf("iterate recovered jobs: %w", err)
	}
	if err := rows.Close(); err != nil {
		return LeaseRecoveryResult{}, fmt.Errorf("close recovered jobs rows: %w", err)
	}
	for requestID := range requestIDs {
		if err := refreshScanRequestStatus(ctx, tx, requestID); err != nil {
			return LeaseRecoveryResult{}, fmt.Errorf("update scan request status after lease recovery: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return LeaseRecoveryResult{}, fmt.Errorf("commit lease recovery: %w", err)
	}
	return result, nil
}

func (r *Repository) UpdateClaimedJobStatus(ctx context.Context, claim domain.ScanJob, status string, finishedAt time.Time, errorMessage *string) (bool, error) {
	if claim.StartedAt == nil || claim.LeaseExpiresAt == nil {
		return false, errors.New("claimed job is missing its claim token")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin claimed job status transaction: %w", err)
	}
	defer tx.Rollback()

	var requestID int64
	err = tx.QueryRowContext(ctx,
		`UPDATE scan_jobs
		 SET status = $1, updated_at = NOW(), finished_at = $2,
		     error_message = $3, lease_expires_at = NULL
		 WHERE id = $4 AND status = 'running' AND started_at = $5 AND lease_expires_at = $6
		 RETURNING request_id`,
		status, finishedAt, nullableString(errorMessage), claim.ID, *claim.StartedAt, *claim.LeaseExpiresAt,
	).Scan(&requestID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("update claimed job status: %w", err)
	}
	if err := refreshScanRequestStatus(ctx, tx, requestID); err != nil {
		return false, fmt.Errorf("update scan request status after job failure: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit claimed job status: %w", err)
	}
	return true, nil
}

func (r *Repository) CompleteJobWithResults(ctx context.Context, claim domain.ScanJob, results []domain.ScanResult, ports [][]domain.ScanPort) error {
	if claim.StartedAt == nil || claim.LeaseExpiresAt == nil {
		return errors.New("claimed job is missing its claim token")
	}
	if len(results) == 0 || len(results) != len(ports) {
		return errors.New("scan results and port groups must be non-empty and have matching lengths")
	}
	for _, result := range results {
		if result.JobID != claim.ID {
			return errors.New("scan result job id does not match claimed job")
		}
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin job completion transaction: %w", err)
	}
	defer tx.Rollback()

	var requestID int64
	err = tx.QueryRowContext(ctx,
		`SELECT request_id FROM scan_jobs
		 WHERE id = $1 AND status = 'running' AND started_at = $2 AND lease_expires_at = $3
		 FOR UPDATE`,
		claim.ID, *claim.StartedAt, *claim.LeaseExpiresAt,
	).Scan(&requestID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrClaimLost
	}
	if err != nil {
		return fmt.Errorf("lock claimed job for completion: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM scan_results WHERE job_id = $1`, claim.ID); err != nil {
		return fmt.Errorf("remove previous results for job: %w", err)
	}
	for resultIndex, result := range results {
		var resultID int64
		if err := tx.QueryRowContext(ctx,
			`INSERT INTO scan_results (job_id, target_value, host_ip, host_status, started_at, finished_at, raw_xml)
			 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
			result.JobID, result.TargetValue, result.HostIP, result.HostStatus,
			result.StartedAt, result.FinishedAt, result.RawXML,
		).Scan(&resultID); err != nil {
			return fmt.Errorf("insert scan result for %s: %w", result.HostIP, err)
		}
		for _, port := range ports[resultIndex] {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO scan_ports (scan_result_id, port, protocol, state, service_name, reason)
				 VALUES ($1, $2, $3, $4, $5, $6)`,
				resultID, port.Port, port.Protocol, port.State,
				nullableString(port.ServiceName), nullableString(port.Reason),
			); err != nil {
				return fmt.Errorf("insert scan port %d/%s: %w", port.Port, port.Protocol, err)
			}
		}
	}

	result, err := tx.ExecContext(ctx,
		`UPDATE scan_jobs SET status = 'completed', updated_at = NOW(), finished_at = NOW(),
		 error_message = NULL, lease_expires_at = NULL
		 WHERE id = $1 AND status = 'running' AND started_at = $2 AND lease_expires_at = $3`,
		claim.ID, *claim.StartedAt, *claim.LeaseExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("mark claimed job completed: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count completed jobs: %w", err)
	}
	if rows != 1 {
		return ErrClaimLost
	}
	if err := refreshScanRequestStatus(ctx, tx, requestID); err != nil {
		return fmt.Errorf("update scan request status after job completion: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit job completion: %w", err)
	}
	return nil
}

func (r *Repository) CreateScanRequestWithJobs(ctx context.Context, req domain.ScanRequest, jobs []domain.ScanJob) (int64, error) {
	if len(jobs) == 0 {
		return 0, errors.New("at least one job is required")
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	var requestID int64
	if err = tx.QueryRowContext(
		ctx,
		`INSERT INTO scan_requests (request_uuid, status) VALUES ($1, $2) RETURNING id`,
		req.RequestUUID,
		req.Status,
	).Scan(&requestID); err != nil {
		return 0, fmt.Errorf("insert scan request: %w", err)
	}

	for _, job := range jobs {
		var jobID int64
		if err = tx.QueryRowContext(
			ctx,
			`INSERT INTO scan_jobs (request_id, target_value, target_type, status, timeout_seconds, attempts, error_message, lease_expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
			requestID,
			job.TargetValue,
			job.TargetType,
			job.Status,
			job.TimeoutSeconds,
			job.Attempts,
			nullableString(job.ErrorMessage),
			nullableTime(job.LeaseExpiresAt),
		).Scan(&jobID); err != nil {
			return 0, fmt.Errorf("insert scan job for %s: %w", job.TargetValue, err)
		}
	}

	if err = tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit request jobs: %w", err)
	}

	return requestID, nil
}

func (r *Repository) UpdateJobStatus(ctx context.Context, jobID int64, status string, startedAt, finishedAt *time.Time, errorMessage *string, leaseExpiresAt *time.Time) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin job status transaction: %w", err)
	}
	defer tx.Rollback()

	var requestID int64
	err = tx.QueryRowContext(
		ctx,
		`UPDATE scan_jobs SET status = $1, updated_at = NOW(), started_at = COALESCE($2, started_at), finished_at = COALESCE($3, finished_at), error_message = $4, lease_expires_at = $5 WHERE id = $6 RETURNING request_id`,
		status,
		nullableTime(startedAt),
		nullableTime(finishedAt),
		nullableString(errorMessage),
		nullableTime(leaseExpiresAt),
		jobID,
	).Scan(&requestID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("update job status: %w", err)
	}
	if err := refreshScanRequestStatus(ctx, tx, requestID); err != nil {
		return fmt.Errorf("update scan request status after job status update: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit job status update: %w", err)
	}
	return nil
}

func (r *Repository) GetJobByID(ctx context.Context, id int64) (*domain.ScanJob, error) {
	row := r.db.QueryRowContext(ctx, `SELECT id, request_id, target_value, target_type, status, created_at, updated_at, started_at, finished_at, timeout_seconds, attempts, error_message, lease_expires_at FROM scan_jobs WHERE id = $1`, id)

	job := &domain.ScanJob{}
	var startedAt, finishedAt, leaseExpiresAt sql.NullTime
	var errorMessage sql.NullString
	if err := row.Scan(
		&job.ID,
		&job.RequestID,
		&job.TargetValue,
		&job.TargetType,
		&job.Status,
		&job.CreatedAt,
		&job.UpdatedAt,
		&startedAt,
		&finishedAt,
		&job.TimeoutSeconds,
		&job.Attempts,
		&errorMessage,
		&leaseExpiresAt,
	); err != nil {
		return nil, fmt.Errorf("select job by id: %w", err)
	}

	job.StartedAt = nullTimeToPtr(startedAt)
	job.FinishedAt = nullTimeToPtr(finishedAt)
	job.LeaseExpiresAt = nullTimeToPtr(leaseExpiresAt)
	job.ErrorMessage = nullStringToPtr(errorMessage)
	return job, nil
}

func (r *Repository) GetJobsByRequestID(ctx context.Context, requestID int64) ([]domain.ScanJob, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, request_id, target_value, target_type, status, created_at, updated_at, started_at, finished_at, timeout_seconds, attempts, error_message, lease_expires_at FROM scan_jobs WHERE request_id = $1 ORDER BY created_at ASC`, requestID)
	if err != nil {
		return nil, fmt.Errorf("select jobs by request id: %w", err)
	}
	defer rows.Close()

	jobs := make([]domain.ScanJob, 0)
	for rows.Next() {
		job := domain.ScanJob{}
		var startedAt, finishedAt, leaseExpiresAt sql.NullTime
		var errorMessage sql.NullString
		if err := rows.Scan(
			&job.ID,
			&job.RequestID,
			&job.TargetValue,
			&job.TargetType,
			&job.Status,
			&job.CreatedAt,
			&job.UpdatedAt,
			&startedAt,
			&finishedAt,
			&job.TimeoutSeconds,
			&job.Attempts,
			&errorMessage,
			&leaseExpiresAt,
		); err != nil {
			return nil, fmt.Errorf("scan rows for request jobs: %w", err)
		}

		job.StartedAt = nullTimeToPtr(startedAt)
		job.FinishedAt = nullTimeToPtr(finishedAt)
		job.LeaseExpiresAt = nullTimeToPtr(leaseExpiresAt)
		job.ErrorMessage = nullStringToPtr(errorMessage)
		jobs = append(jobs, job)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate request jobs: %w", err)
	}

	return jobs, nil
}

func (r *Repository) SaveScanResultWithPorts(ctx context.Context, result domain.ScanResult, ports []domain.ScanPort) (int64, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin transaction for scan result: %w", err)
	}
	defer tx.Rollback()

	var resultID int64
	if err = tx.QueryRowContext(
		ctx,
		`INSERT INTO scan_results (job_id, target_value, host_ip, host_status, started_at, finished_at, raw_xml) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		result.JobID,
		result.TargetValue,
		result.HostIP,
		result.HostStatus,
		result.StartedAt,
		result.FinishedAt,
		result.RawXML,
	).Scan(&resultID); err != nil {
		return 0, fmt.Errorf("insert scan result: %w", err)
	}

	for _, port := range ports {
		_, err = tx.ExecContext(
			ctx,
			`INSERT INTO scan_ports (scan_result_id, port, protocol, state, service_name, reason) VALUES ($1, $2, $3, $4, $5, $6)`,
			resultID,
			port.Port,
			port.Protocol,
			port.State,
			nullableString(port.ServiceName),
			nullableString(port.Reason),
		)
		if err != nil {
			return 0, fmt.Errorf("insert scan port %d/%s: %w", port.Port, port.Protocol, err)
		}
	}

	if err = tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit scan result and ports: %w", err)
	}

	return resultID, nil
}

func nullableString(value *string) sql.NullString {
	if value == nil {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: *value, Valid: true}
}

func nullableTime(value *time.Time) sql.NullTime {
	if value == nil {
		return sql.NullTime{Valid: false}
	}
	return sql.NullTime{Time: *value, Valid: true}
}

func nullTimeToPtr(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	v := value.Time
	return &v
}

func nullStringToPtr(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	v := value.String
	return &v
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanJob(row rowScanner) (domain.ScanJob, error) {
	var job domain.ScanJob
	var startedAt, finishedAt, leaseExpiresAt sql.NullTime
	var errorMessage sql.NullString
	if err := row.Scan(
		&job.ID,
		&job.RequestID,
		&job.TargetValue,
		&job.TargetType,
		&job.Status,
		&job.CreatedAt,
		&job.UpdatedAt,
		&startedAt,
		&finishedAt,
		&job.TimeoutSeconds,
		&job.Attempts,
		&errorMessage,
		&leaseExpiresAt,
	); err != nil {
		return domain.ScanJob{}, err
	}
	job.StartedAt = nullTimeToPtr(startedAt)
	job.FinishedAt = nullTimeToPtr(finishedAt)
	job.LeaseExpiresAt = nullTimeToPtr(leaseExpiresAt)
	job.ErrorMessage = nullStringToPtr(errorMessage)
	return job, nil
}

func refreshScanRequestStatus(ctx context.Context, tx *sql.Tx, requestID int64) error {
	var lockedID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM scan_requests WHERE id = $1 FOR UPDATE`, requestID).Scan(&lockedID); err != nil {
		return fmt.Errorf("lock scan request %d: %w", requestID, err)
	}

	var total, pending, running, failed, timedOut int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*),
		        COUNT(*) FILTER (WHERE status = 'pending'),
		        COUNT(*) FILTER (WHERE status = 'running'),
		        COUNT(*) FILTER (WHERE status = 'failed'),
		        COUNT(*) FILTER (WHERE status = 'timed_out')
		 FROM scan_jobs WHERE request_id = $1`,
		requestID,
	).Scan(&total, &pending, &running, &failed, &timedOut); err != nil {
		return fmt.Errorf("aggregate scan request %d jobs: %w", requestID, err)
	}
	if total == 0 {
		return fmt.Errorf("scan request %d has no jobs", requestID)
	}

	status, err := deriveScanRequestStatus(total, pending, running, failed, timedOut)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE scan_requests SET status = $1, updated_at = NOW() WHERE id = $2`, status, requestID); err != nil {
		return fmt.Errorf("update scan request %d status: %w", requestID, err)
	}
	return nil
}

func deriveScanRequestStatus(total, pending, running, failed, timedOut int64) (string, error) {
	if total <= 0 {
		return "", errors.New("scan request has no jobs")
	}
	switch {
	case pending == total:
		return "pending", nil
	case pending > 0 || running > 0:
		return "running", nil
	case failed > 0:
		return "failed", nil
	case timedOut > 0:
		return "timed_out", nil
	default:
		return "completed", nil
	}
}
