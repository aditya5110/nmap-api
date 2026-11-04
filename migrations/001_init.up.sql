CREATE TABLE scan_requests (
    id BIGSERIAL PRIMARY KEY,
    request_uuid UUID NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed', 'timed_out'))
);

CREATE TABLE scan_jobs (
    id BIGSERIAL PRIMARY KEY,
    request_id BIGINT NOT NULL REFERENCES scan_requests(id) ON DELETE CASCADE,
    target_value TEXT NOT NULL,
    target_type TEXT NOT NULL CHECK (target_type IN ('ip', 'hostname')),
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed', 'timed_out')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ NULL,
    finished_at TIMESTAMPTZ NULL,
    timeout_seconds INTEGER NOT NULL DEFAULT 120,
    attempts INTEGER NOT NULL DEFAULT 0,
    error_message TEXT NULL,
    lease_expires_at TIMESTAMPTZ NULL
);

CREATE INDEX idx_scan_jobs_request_id ON scan_jobs(request_id);
CREATE INDEX idx_scan_jobs_status_created_at ON scan_jobs(status, created_at);
CREATE INDEX idx_scan_jobs_target_value ON scan_jobs(target_value);

CREATE TABLE scan_results (
    id BIGSERIAL PRIMARY KEY,
    job_id BIGINT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    target_value TEXT NOT NULL,
    host_ip TEXT NOT NULL,
    host_status TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ NOT NULL,
    raw_xml TEXT NOT NULL,
    UNIQUE (job_id, host_ip)
);

CREATE INDEX idx_scan_results_host_ip_finished_at ON scan_results(host_ip, finished_at DESC);

CREATE TABLE scan_ports (
    id BIGSERIAL PRIMARY KEY,
    scan_result_id BIGINT NOT NULL REFERENCES scan_results(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state <> ''),
    service_name TEXT NULL,
    reason TEXT NULL,
    UNIQUE (scan_result_id, port, protocol)
);

