package db

import (
	"context"
	"database/sql"
	"fmt"

	"nmap-api/internal/domain"
)

func (r *Repository) GetScanHistory(ctx context.Context, target string, limit int) ([]domain.ScanHistory, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("history limit must be greater than zero")
	}
	rows, err := r.db.QueryContext(ctx,
		`WITH recent_jobs AS (
			SELECT j.id, j.status, j.started_at, j.finished_at, j.created_at
			FROM scan_jobs AS j
			WHERE LOWER(RTRIM(j.target_value, '.')) = LOWER(RTRIM($1, '.'))
			   OR EXISTS (
					SELECT 1 FROM scan_results AS matched
					WHERE matched.job_id = j.id AND matched.host_ip = $1
				)
			ORDER BY COALESCE(j.finished_at, j.started_at, j.created_at) DESC, j.id DESC
			LIMIT $2
		)
		SELECT j.id, j.status, j.started_at, j.finished_at,
		       sr.host_ip, sr.host_status, sp.port, sp.protocol, sp.state, sp.service_name, sp.reason
		FROM recent_jobs AS j
		LEFT JOIN scan_results AS sr ON sr.job_id = j.id
		LEFT JOIN scan_ports AS sp ON sp.scan_result_id = sr.id
		ORDER BY COALESCE(j.finished_at, j.started_at, j.created_at) DESC,
		         j.id DESC, sr.host_ip ASC, sp.protocol ASC, sp.port ASC`,
		target, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query scan history: %w", err)
	}
	defer rows.Close()
	return scanHistoryRows(rows)
}

func (r *Repository) GetLatestComparableScans(ctx context.Context, target string) ([]domain.ScanHistory, error) {
	rows, err := r.db.QueryContext(ctx,
		`WITH completed_scans AS (
			SELECT j.id, j.started_at, j.finished_at,
			       ARRAY_AGG(sr.host_ip ORDER BY sr.host_ip) AS resolved_ips
			FROM scan_jobs AS j
			JOIN scan_results AS sr ON sr.job_id = j.id
			WHERE j.status = 'completed'
			  AND j.started_at IS NOT NULL
			  AND j.finished_at IS NOT NULL
			  AND (
				LOWER(RTRIM(j.target_value, '.')) = LOWER(RTRIM($1, '.'))
				OR EXISTS (
					SELECT 1 FROM scan_results AS matched
					WHERE matched.job_id = j.id AND matched.host_ip = $1
				)
			  )
			GROUP BY j.id, j.started_at, j.finished_at
		), comparable_pairs AS (
			SELECT older.id AS previous_id, newer.id AS current_id
			FROM completed_scans AS older
			JOIN completed_scans AS newer
			  ON older.resolved_ips = newer.resolved_ips
			 AND (older.finished_at < newer.finished_at
			      OR (older.finished_at = newer.finished_at AND older.id < newer.id))
			ORDER BY newer.finished_at DESC, newer.id DESC, older.finished_at DESC, older.id DESC
			LIMIT 1
		), selected_scans AS (
			SELECT previous_id AS id, 0 AS scan_order FROM comparable_pairs
			UNION ALL
			SELECT current_id AS id, 1 AS scan_order FROM comparable_pairs
		)
		SELECT j.id, j.status, j.started_at, j.finished_at,
		       sr.host_ip, sr.host_status, sp.port, sp.protocol, sp.state, sp.service_name, sp.reason
		FROM selected_scans AS selected
		JOIN scan_jobs AS j ON j.id = selected.id
		LEFT JOIN scan_results AS sr ON sr.job_id = j.id
		LEFT JOIN scan_ports AS sp ON sp.scan_result_id = sr.id
		ORDER BY selected.scan_order, sr.host_ip ASC, sp.protocol ASC, sp.port ASC`,
		target,
	)
	if err != nil {
		return nil, fmt.Errorf("query comparable scan history: %w", err)
	}
	defer rows.Close()
	return scanHistoryRows(rows)
}

func scanHistoryRows(rows *sql.Rows) ([]domain.ScanHistory, error) {
	history := make([]domain.ScanHistory, 0)
	resolvedIPs := make(map[int64]map[string]struct{})

	for rows.Next() {
		var scanID int64
		var status string
		var startedAt, finishedAt sql.NullTime
		var hostIP, hostStatus, protocol, state, service, reason sql.NullString
		var port sql.NullInt64
		if err := rows.Scan(&scanID, &status, &startedAt, &finishedAt, &hostIP, &hostStatus, &port, &protocol, &state, &service, &reason); err != nil {
			return nil, fmt.Errorf("scan history row: %w", err)
		}

		if len(history) == 0 || history[len(history)-1].ScanID != scanID {
			history = append(history, domain.ScanHistory{
				ScanID:       scanID,
				StartedAt:    nullTimeToPtr(startedAt),
				FinishedAt:   nullTimeToPtr(finishedAt),
				Status:       status,
				ResolvedIPs:  make([]string, 0),
				Ports:        make([]domain.ObservedScanPort, 0),
				HostStatuses: make(map[string]string),
			})
			resolvedIPs[scanID] = make(map[string]struct{})
		}

		if hostIP.Valid {
			if hostStatus.Valid {
				history[len(history)-1].HostStatuses[hostIP.String] = hostStatus.String
			}
			if _, seen := resolvedIPs[scanID][hostIP.String]; !seen {
				resolvedIPs[scanID][hostIP.String] = struct{}{}
				history[len(history)-1].ResolvedIPs = append(history[len(history)-1].ResolvedIPs, hostIP.String)
			}
			if port.Valid {
				history[len(history)-1].Ports = append(history[len(history)-1].Ports, domain.ObservedScanPort{
					ResolvedIP: hostIP.String,
					Port:       int(port.Int64),
					Protocol:   protocol.String,
					State:      state.String,
					Service:    nullStringToPtr(service),
					Reason:     nullStringToPtr(reason),
				})
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scan history rows: %w", err)
	}
	return history, nil
}
