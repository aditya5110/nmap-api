//go:build integration

package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
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
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

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

	if _, err := db.ExecContext(ctx, `SET search_path TO "`+schema+`"`); err != nil {
		t.Fatalf("set isolated PostgreSQL integration schema: %v", err)
	}
	if err := applyInitialMigration(ctx, db); err != nil {
		t.Fatalf("apply initial PostgreSQL migration: %v", err)
	}

	return db, NewRepository(db), ctx
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
