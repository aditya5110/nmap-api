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

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
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
	_, err := r.db.ExecContext(
		ctx,
		`UPDATE scan_jobs SET status = $1, updated_at = NOW(), started_at = COALESCE($2, started_at), finished_at = COALESCE($3, finished_at), error_message = $4, lease_expires_at = $5 WHERE id = $6`,
		status,
		nullableTime(startedAt),
		nullableTime(finishedAt),
		nullableString(errorMessage),
		nullableTime(leaseExpiresAt),
		jobID,
	)
	if err != nil {
		return fmt.Errorf("update job status: %w", err)
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
