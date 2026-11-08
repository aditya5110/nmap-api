# nmap-api

Go REST API for submitting authorized Nmap scans. Scan requests are stored in PostgreSQL and processed by the bounded worker pool.

## Local development

### Prerequisites

- Docker and Docker Compose
- Go 1.22+

### Build and run with Docker Compose

Copy the example environment file, then set a unique local database password and the exact targets you are authorized to scan. An empty `SCAN_ALLOWED_TARGETS` denies all scan requests.

```bash
cp .env.example .env
# Edit .env and replace DB_PASSWORD with a unique local password.
docker compose up --build -d
docker compose exec -T postgres psql -U appuser -d nmapdb < migrations/001_init.up.sql
```

`docker compose up --build -d` starts the PostgreSQL and API containers. Docker Compose automatically reads `.env` for `${...}` interpolation in `docker-compose.yml` and passes the configured values into the containers. The API listens on port 8080.

The migration command runs `migrations/001_init.up.sql` against PostgreSQL in the `postgres` container. It creates the tables, indexes, and constraints required by the application. Migrations do not run automatically; apply this migration once when initializing a fresh database. If you customize `DB_USER` or `DB_NAME` in `.env`, update `appuser` or `nmapdb` in the command to match.

`SCAN_ALLOWED_TARGETS` is a comma-separated list of exact IPv4, IPv6, or hostname entries. IPs are normalized and hostnames are matched case-insensitively. Wildcards and CIDR ranges are not supported. The API does not perform DNS resolution while validating requests.

Only scan systems for which you have explicit authorization. The allowlist is a target-scope safeguard, not an authentication system. Any public deployment requires appropriate access controls and network restrictions.

### Run the Go app directly

The Go application does not load `.env` itself. When running it directly, export the required variables in the shell (or source a trusted local env file) before starting it:

```bash
export DB_HOST=localhost DB_PORT=5432 DB_USER=appuser DB_NAME=nmapdb
export DB_PASSWORD='choose-a-local-password'
export SCAN_ALLOWED_TARGETS='127.0.0.1,::1'
go run ./cmd/api
```

### Submit a scan

```bash
curl -X POST http://localhost:8080/api/v1/scans \
	-H 'Content-Type: application/json' \
	-d '{"targets":["127.0.0.1"],"timeout_seconds":60}'
```

### Retrieve recent scans

`GET /api/v1/targets/{target}/scans` returns the newest scans first. The optional `limit` is between 1 and 100; it defaults to 20.

```bash
curl 'http://localhost:8080/api/v1/targets/127.0.0.1/scans?limit=10'
```

Example response:

```json
{
	"target": "127.0.0.1",
	"scans": [
		{
			"scan_id": 42,
			"started_at": "2026-11-05T12:00:00Z",
			"finished_at": "2026-11-05T12:00:18Z",
			"status": "completed",
			"resolved_ips": ["127.0.0.1"],
			"ports": [
				{"resolved_ip": "127.0.0.1", "port": 80, "protocol": "tcp", "state": "open", "service": "http"}
			]
		}
	]
}
```

No matching history returns `200 OK` with an empty `scans` array.

### Compare recent scans

`GET /api/v1/targets/{target}/changes` compares the two most recent completed scans that resolved to the same IP-address set. Port identity includes resolved IP, protocol, and port number. A missing observation is not converted into a `closed` state; removed-port entries retain the prior observed state.

```bash
curl 'http://localhost:8080/api/v1/targets/127.0.0.1/changes'
```

Example response:

```json
{
	"target": "127.0.0.1",
	"previous_scan_id": 41,
	"current_scan_id": 42,
	"previous_started_at": "2026-11-05T11:00:00Z",
	"previous_finished_at": "2026-11-05T11:00:12Z",
	"current_started_at": "2026-11-05T12:00:00Z",
	"current_finished_at": "2026-11-05T12:00:18Z",
	"added_ports": [],
	"removed_ports": [],
	"changed_ports": [
		{
			"resolved_ip": "127.0.0.1",
			"port": 80,
			"protocol": "tcp",
			"previous_state": "filtered",
			"current_state": "open",
			"previous_service": "http",
			"current_service": "http"
		}
	]
}
```

If two comparable completed scans are unavailable, the endpoint returns `404 Not Found`.

### Testing the API with Postman

Open Postman and create a new HTTP request. For each request below, select the listed method, enter the URL, click **Send**, then inspect both the response body and HTTP status code. Start the API and apply the database migration first. The scan target must also be included in `SCAN_ALLOWED_TARGETS`.

#### 1. Submit a scan

- **Method:** `POST`
- **URL:** `http://localhost:8080/api/v1/scans`
- In **Headers**, set `Content-Type` to `application/json`.
- In **Body**, select **raw**, choose **JSON**, and enter:

```json
{
	"targets": ["127.0.0.1"],
	"timeout_seconds": 60
}
```

A successful request returns `202 Accepted` after the scan request and job are saved. Scanning is asynchronous, so this response means the job was accepted, not that scanning has finished.

```json
{
	"request_id": "6e0aa93a-4d0a-45ac-8ff0-ace0e1480e2c",
	"status": "accepted",
	"targets": [
		{"target": "127.0.0.1", "status": "pending"}
	]
}
```

#### 2. Retrieve recent scans

- **Method:** `GET`
- **URL:** `http://localhost:8080/api/v1/targets/127.0.0.1/scans?limit=10`

The optional `limit` query parameter controls how many recent scans are returned. It defaults to `20` when omitted and must be between `1` and `100`.

```json
{
	"target": "127.0.0.1",
	"scans": [
		{
			"scan_id": 42,
			"started_at": "2026-11-05T12:00:00Z",
			"finished_at": "2026-11-05T12:00:18Z",
			"status": "completed",
			"resolved_ips": ["127.0.0.1"],
			"ports": [
				{"resolved_ip": "127.0.0.1", "port": 80, "protocol": "tcp", "state": "open", "service": "http"}
			]
		}
	]
}
```

No matching history returns `200 OK` with an empty `scans` array.

#### 3. Compare recent scans

- **Method:** `GET`
- **URL:** `http://localhost:8080/api/v1/targets/127.0.0.1/changes`

This compares the two most recent comparable completed scans, which must have resolved to the same IP-address set. If two such scans are unavailable, the endpoint returns `404 Not Found` with an error response.

```json
{
	"target": "127.0.0.1",
	"previous_scan_id": 41,
	"current_scan_id": 42,
	"previous_started_at": "2026-11-05T11:00:00Z",
	"previous_finished_at": "2026-11-05T11:00:12Z",
	"current_started_at": "2026-11-05T12:00:00Z",
	"current_finished_at": "2026-11-05T12:00:18Z",
	"added_ports": [],
	"removed_ports": [],
	"changed_ports": [
		{
			"resolved_ip": "127.0.0.1",
			"port": 80,
			"protocol": "tcp",
			"previous_state": "filtered",
			"current_state": "open",
			"previous_service": "http",
			"current_service": "http"
		}
	]
}
```

The `404 Not Found` response when no comparable pair is available is:

```json
{
	"error": {
		"code": "NO_COMPARABLE_SCANS",
		"message": "fewer than two comparable completed scans are available"
	}
}
```

### Run tests

```bash
go test ./...
```

