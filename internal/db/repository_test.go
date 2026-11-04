package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"nmap-api/internal/config"
	"nmap-api/internal/domain"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestPGXConfigEscapesCredentials(t *testing.T) {
	cfg, err := pgxConfig(config.Config{
		DBHost:     "localhost",
		DBPort:     5432,
		DBUser:     "user@name",
		DBPassword: "p@ss:/?#% with spaces",
		DBName:     "nmap db",
		DBSSLMode:  "disable",
	})
	if err != nil {
		t.Fatalf("pgxConfig returned error: %v", err)
	}
	if cfg.User != "user@name" {
		t.Errorf("expected user to round-trip, got %q", cfg.User)
	}
	if cfg.Password != "p@ss:/?#% with spaces" {
		t.Errorf("expected password to round-trip, got %q", cfg.Password)
	}
	if cfg.Database != "nmap db" {
		t.Errorf("expected database name to round-trip, got %q", cfg.Database)
	}
}

func TestCreateScanRequestWithJobs(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	request := domain.ScanRequest{RequestUUID: "6e0aa93a-4d0a-45ac-8ff0-ace0e1480e2c", Status: "pending"}
	jobs := []domain.ScanJob{{TargetValue: "8.8.8.8", TargetType: "ip", Status: "pending", TimeoutSeconds: 120}}

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO scan_requests").WithArgs(request.RequestUUID, request.Status).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(77)))
	mock.ExpectQuery("INSERT INTO scan_jobs").WithArgs(int64(77), jobs[0].TargetValue, jobs[0].TargetType, jobs[0].Status, jobs[0].TimeoutSeconds, 0, sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(11)))
	mock.ExpectCommit()

	id, err := repo.CreateScanRequestWithJobs(context.Background(), request, jobs)
	if err != nil {
		t.Fatalf("CreateScanRequestWithJobs returned error: %v", err)
	}
	if id != 77 {
		t.Fatalf("expected request id 77, got %d", id)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestCreateScanRequestWithJobs_RequiresJobs(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	_, err = repo.CreateScanRequestWithJobs(context.Background(), domain.ScanRequest{}, nil)
	if err == nil || err.Error() != "at least one job is required" {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func TestCreateScanRequestWithJobs_RollsBackAfterJobInsertFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	request := domain.ScanRequest{RequestUUID: "6e0aa93a-4d0a-45ac-8ff0-ace0e1480e2c", Status: "pending"}
	jobs := []domain.ScanJob{
		{TargetValue: "8.8.8.8", TargetType: "ip", Status: "pending", TimeoutSeconds: 120},
		{TargetValue: "example.com", TargetType: "hostname", Status: "invalid", TimeoutSeconds: 120},
	}

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO scan_requests").WithArgs(request.RequestUUID, request.Status).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(77)))
	mock.ExpectQuery("INSERT INTO scan_jobs").WithArgs(int64(77), jobs[0].TargetValue, jobs[0].TargetType, jobs[0].Status, jobs[0].TimeoutSeconds, 0, sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(11)))
	mock.ExpectQuery("INSERT INTO scan_jobs").WithArgs(int64(77), jobs[1].TargetValue, jobs[1].TargetType, jobs[1].Status, jobs[1].TimeoutSeconds, 0, sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnError(errors.New("constraint violation"))
	mock.ExpectRollback()

	if _, err := repo.CreateScanRequestWithJobs(context.Background(), request, jobs); err == nil {
		t.Fatal("expected second job insert to fail")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestClaimNextJob_CommitsClaim(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	started := time.Now().UTC()
	lease := started.Add(150 * time.Second)
	now := started.Add(-time.Minute)

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT id FROM scan_jobs").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(25)))
	mock.ExpectQuery("UPDATE scan_jobs").WithArgs(int64(150000), int64(25)).WillReturnRows(sqlmock.NewRows([]string{
		"id", "request_id", "target_value", "target_type", "status", "created_at", "updated_at", "started_at", "finished_at", "timeout_seconds", "attempts", "error_message", "lease_expires_at",
	}).AddRow(int64(25), int64(3), "scanme.nmap.org", "hostname", "running", now, started, started, nil, 120, 1, nil, lease))
	expectRequestStatus(mock, int64(3), "running", 2, 1, 1, 0, 0)
	mock.ExpectCommit()

	job, err := repo.ClaimNextJob(context.Background(), 150*time.Second)
	if err != nil {
		t.Fatalf("ClaimNextJob returned error: %v", err)
	}
	if job == nil || job.ID != 25 || job.Status != "running" || job.Attempts != 1 {
		t.Fatalf("unexpected claimed job: %#v", job)
	}
	if job.StartedAt == nil || !job.StartedAt.Equal(started) || job.LeaseExpiresAt == nil || !job.LeaseExpiresAt.Equal(lease) {
		t.Fatalf("claim timestamps were not returned: %#v", job)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestClaimNextJob_RollsBackWhenUpdateFails(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT id FROM scan_jobs").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(25)))
	mock.ExpectQuery("UPDATE scan_jobs").WithArgs(int64(150000), int64(25)).WillReturnError(errors.New("database error"))
	mock.ExpectRollback()

	if _, err := repo.ClaimNextJob(context.Background(), 150*time.Second); err == nil {
		t.Fatal("expected claim update failure")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestClaimNextJob_NoAvailableJob(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT id FROM scan_jobs").WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	job, err := repo.ClaimNextJob(context.Background(), 150*time.Second)
	if err != nil || job != nil {
		t.Fatalf("expected no job and no error, got job=%v err=%v", job, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestRecoverExpiredJobs(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	mock.ExpectBegin()
	mock.ExpectQuery("UPDATE scan_jobs").WithArgs(MaxJobAttempts).WillReturnRows(sqlmock.NewRows([]string{"request_id"}).AddRow(int64(3)).AddRow(int64(3)))
	expectRequestStatus(mock, int64(3), "running", 2, 1, 0, 1, 0)
	mock.ExpectCommit()
	count, err := repo.RecoverExpiredJobs(context.Background())
	if err != nil || count != 2 {
		t.Fatalf("expected two recovered jobs, count=%d err=%v", count, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestUpdateClaimedJobStatus_FencesStaleClaim(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	started := time.Now().UTC()
	lease := started.Add(150 * time.Second)
	claim := domain.ScanJob{ID: 8, StartedAt: &started, LeaseExpiresAt: &lease}
	mock.ExpectBegin()
	mock.ExpectQuery("UPDATE scan_jobs").WithArgs("failed", sqlmock.AnyArg(), sqlmock.AnyArg(), int64(8), started, lease).WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	updated, err := repo.UpdateClaimedJobStatus(context.Background(), claim, "failed", time.Now().UTC(), nil)
	if err != nil || updated {
		t.Fatalf("expected stale claim to update no row, updated=%v err=%v", updated, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestCompleteJobWithResults_Transactional(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	started := time.Now().UTC()
	lease := started.Add(150 * time.Second)
	claim := domain.ScanJob{ID: 9, StartedAt: &started, LeaseExpiresAt: &lease}
	result := domain.ScanResult{JobID: 9, TargetValue: "example.com", HostIP: "192.0.2.1", HostStatus: "up", StartedAt: started, FinishedAt: lease, RawXML: "xml"}
	ports := [][]domain.ScanPort{{{Port: 80, Protocol: "tcp", State: "open"}}}

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT request_id FROM scan_jobs").WithArgs(int64(9), started, lease).WillReturnRows(sqlmock.NewRows([]string{"request_id"}).AddRow(int64(3)))
	mock.ExpectExec("DELETE FROM scan_results").WithArgs(int64(9)).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("INSERT INTO scan_results").WithArgs(int64(9), "example.com", "192.0.2.1", "up", started, lease, "xml").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(44)))
	mock.ExpectExec("INSERT INTO scan_ports").WithArgs(int64(44), 80, "tcp", "open", sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE scan_jobs").WithArgs(int64(9), started, lease).WillReturnResult(sqlmock.NewResult(0, 1))
	expectRequestStatus(mock, int64(3), "completed", 1, 0, 0, 0, 0)
	mock.ExpectCommit()

	if err := repo.CompleteJobWithResults(context.Background(), claim, []domain.ScanResult{result}, ports); err != nil {
		t.Fatalf("CompleteJobWithResults returned error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestCompleteJobWithResults_RollsBackOnPortFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	started := time.Now().UTC()
	lease := started.Add(150 * time.Second)
	claim := domain.ScanJob{ID: 9, StartedAt: &started, LeaseExpiresAt: &lease}
	result := domain.ScanResult{JobID: 9, TargetValue: "example.com", HostIP: "192.0.2.1", HostStatus: "up", StartedAt: started, FinishedAt: lease, RawXML: "xml"}
	ports := [][]domain.ScanPort{{{Port: 80, Protocol: "tcp", State: "open"}}}

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT request_id FROM scan_jobs").WithArgs(int64(9), started, lease).WillReturnRows(sqlmock.NewRows([]string{"request_id"}).AddRow(int64(3)))
	mock.ExpectExec("DELETE FROM scan_results").WithArgs(int64(9)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("INSERT INTO scan_results").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(44)))
	mock.ExpectExec("INSERT INTO scan_ports").WillReturnError(errors.New("constraint violation"))
	mock.ExpectRollback()

	if err := repo.CompleteJobWithResults(context.Background(), claim, []domain.ScanResult{result}, ports); err == nil {
		t.Fatal("expected port insertion failure")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestUpdateJobStatus(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	started := time.Now().UTC().Truncate(time.Second)
	finished := started.Add(30 * time.Second)
	errorText := "timeout"
	lease := finished.Add(30 * time.Second)

	mock.ExpectBegin()
	mock.ExpectQuery("UPDATE scan_jobs").WithArgs("completed", started, finished, errorText, lease, int64(42)).WillReturnRows(sqlmock.NewRows([]string{"request_id"}).AddRow(int64(7)))
	expectRequestStatus(mock, int64(7), "completed", 1, 0, 0, 0, 0)
	mock.ExpectCommit()

	if err := repo.UpdateJobStatus(context.Background(), 42, "completed", &started, &finished, &errorText, &lease); err != nil {
		t.Fatalf("UpdateJobStatus returned error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestGetJobsByRequestID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	started := time.Now().UTC().Truncate(time.Second)
	finished := started.Add(2 * time.Minute)
	errorText := "scan limit reached"
	rows := sqlmock.NewRows([]string{"id", "request_id", "target_value", "target_type", "status", "created_at", "updated_at", "started_at", "finished_at", "timeout_seconds", "attempts", "error_message", "lease_expires_at"})
	rows.AddRow(int64(10), int64(7), "scanme.nmap.org", "hostname", "completed", time.Now().UTC(), time.Now().UTC(), started, finished, 120, 1, errorText, finished.Add(10*time.Minute))
	mock.ExpectQuery("SELECT id, request_id, target_value, target_type, status").WithArgs(int64(7)).WillReturnRows(rows)

	jobs, err := repo.GetJobsByRequestID(context.Background(), 7)
	if err != nil {
		t.Fatalf("GetJobsByRequestID returned error: %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("expected 1 job, got %d", len(jobs))
	}
	if jobs[0].TargetValue != "scanme.nmap.org" {
		t.Fatalf("expected target scanme.nmap.org, got %s", jobs[0].TargetValue)
	}
	if jobs[0].ErrorMessage == nil || *jobs[0].ErrorMessage != errorText {
		t.Fatalf("expected error message %q, got %v", errorText, jobs[0].ErrorMessage)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestSaveScanResultWithPorts(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	started := time.Now().UTC().Truncate(time.Second)
	finished := started.Add(3 * time.Second)
	result := domain.ScanResult{JobID: 9, TargetValue: "example.com", HostIP: "93.184.216.34", HostStatus: "up", StartedAt: started, FinishedAt: finished, RawXML: "<nmap></nmap>"}
	ports := []domain.ScanPort{{Port: 80, Protocol: "tcp", State: "open", ServiceName: strPtr("http"), Reason: strPtr("syn-ack")}}

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO scan_results").WithArgs(result.JobID, result.TargetValue, result.HostIP, result.HostStatus, result.StartedAt, result.FinishedAt, result.RawXML).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(42)))
	mock.ExpectExec("INSERT INTO scan_ports").WithArgs(int64(42), ports[0].Port, ports[0].Protocol, ports[0].State, sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	id, err := repo.SaveScanResultWithPorts(context.Background(), result, ports)
	if err != nil {
		t.Fatalf("SaveScanResultWithPorts returned error: %v", err)
	}
	if id != 42 {
		t.Fatalf("expected result id 42, got %d", id)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestSaveScanResultWithPorts_RollsBackAfterPortInsertFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	started := time.Now().UTC().Truncate(time.Second)
	finished := started.Add(3 * time.Second)
	result := domain.ScanResult{JobID: 9, TargetValue: "example.com", HostIP: "93.184.216.34", HostStatus: "up", StartedAt: started, FinishedAt: finished, RawXML: "<nmap></nmap>"}
	ports := []domain.ScanPort{
		{Port: 80, Protocol: "tcp", State: "open"},
		{Port: 443, Protocol: "tcp", State: "open"},
	}

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO scan_results").WithArgs(result.JobID, result.TargetValue, result.HostIP, result.HostStatus, result.StartedAt, result.FinishedAt, result.RawXML).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(42)))
	mock.ExpectExec("INSERT INTO scan_ports").WithArgs(int64(42), ports[0].Port, ports[0].Protocol, ports[0].State, sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO scan_ports").WithArgs(int64(42), ports[1].Port, ports[1].Protocol, ports[1].State, sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnError(errors.New("constraint violation"))
	mock.ExpectRollback()

	if _, err := repo.SaveScanResultWithPorts(context.Background(), result, ports); err == nil {
		t.Fatal("expected second port insert to fail")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestNullConversions(t *testing.T) {
	if got := nullableTime(nil); got.Valid {
		t.Fatal("expected invalid nullable time for nil")
	}
	if got := nullableString(nil); got.Valid {
		t.Fatal("expected invalid nullable string for nil")
	}

	msg := "ok"
	tm := time.Now().UTC()
	if got := nullableString(&msg); !got.Valid || got.String != msg {
		t.Fatalf("expected valid string, got %#v", got)
	}
	if got := nullableTime(&tm); !got.Valid || !got.Time.Equal(tm) {
		t.Fatalf("expected valid time, got %#v", got)
	}
	if got := nullStringToPtr(sql.NullString{String: "value", Valid: true}); got == nil || *got != "value" {
		t.Fatalf("expected converted string pointer, got %v", got)
	}
	if got := nullTimeToPtr(sql.NullTime{Time: tm, Valid: true}); got == nil || !got.Equal(tm) {
		t.Fatalf("expected converted time pointer, got %v", got)
	}
	if got := nullStringToPtr(sql.NullString{Valid: false}); got != nil {
		t.Fatalf("expected nil for invalid null string, got %v", got)
	}
	if got := nullTimeToPtr(sql.NullTime{Valid: false}); got != nil {
		t.Fatalf("expected nil for invalid null time, got %v", got)
	}
}

func TestGetJobByID_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	mock.ExpectQuery("SELECT id, request_id, target_value, target_type, status").WithArgs(int64(99)).WillReturnError(errors.New("sql: no rows in result set"))
	if _, err := repo.GetJobByID(context.Background(), 99); err == nil {
		t.Fatal("expected error when job is missing")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func strPtr(v string) *string {
	return &v
}

func expectRequestStatus(mock sqlmock.Sqlmock, requestID int64, status string, total, pending, running, failed, timedOut int64) {
	mock.ExpectQuery("SELECT id FROM scan_requests WHERE id = \\$1 FOR UPDATE").WithArgs(requestID).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(requestID))
	mock.ExpectQuery("SELECT COUNT\\(\\*\\)").WithArgs(requestID).
		WillReturnRows(sqlmock.NewRows([]string{"total", "pending", "running", "failed", "timed_out"}).AddRow(total, pending, running, failed, timedOut))
	mock.ExpectExec("UPDATE scan_requests SET status").WithArgs(status, requestID).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

func TestDeriveScanRequestStatus(t *testing.T) {
	tests := []struct {
		name                            string
		total, pending, running, failed int64
		timedOut                        int64
		want                            string
	}{
		{name: "all pending", total: 3, pending: 3, want: "pending"},
		{name: "running", total: 3, pending: 1, running: 1, failed: 1, want: "running"},
		{name: "pending mixed with terminal", total: 2, pending: 1, failed: 1, want: "running"},
		{name: "all completed", total: 2, want: "completed"},
		{name: "completed and timed out", total: 2, timedOut: 1, want: "timed_out"},
		{name: "failed takes precedence", total: 3, failed: 1, timedOut: 1, want: "failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := deriveScanRequestStatus(test.total, test.pending, test.running, test.failed, test.timedOut)
			if err != nil || got != test.want {
				t.Fatalf("deriveScanRequestStatus() = %q, %v; want %q", got, err, test.want)
			}
		})
	}
	if _, err := deriveScanRequestStatus(0, 0, 0, 0, 0); err == nil {
		t.Fatal("expected zero-job request to be rejected")
	}
}
