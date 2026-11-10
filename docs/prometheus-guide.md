# Prometheus metrics guide

## What Prometheus collects

Prometheus is a separate Docker Compose service. It scrapes the API at `api:8080` every 15 seconds and stores time-series data in the `prometheus_data` volume. PostgreSQL remains the source of truth for scan requests, jobs, results, and ports; Prometheus stores metrics, not scan history.

The API exposes Prometheus text exposition at `GET /metrics` (not JSON). The metrics handler is separate from application routes, and requests to `/metrics` are excluded from application HTTP metrics.

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `http_requests_total` | Counter | `method`, normalized `route`, `status_code` | Completed application HTTP requests. |
| `http_request_duration_seconds` | Histogram | `method`, normalized `route`, `status_code` | Request handling duration. Prometheus also exposes `_bucket`, `_sum`, and `_count` series. |
| `http_requests_in_flight` | Gauge | `method`, normalized `route` | Requests currently being handled. |
| `scan_jobs_total` | Counter | `outcome` | Persisted terminal outcomes: `completed`, `failed`, `timed_out`. Requeued lease-expired jobs are not counted as failed. |
| `nmap_execution_duration_seconds` | Histogram | None | Time in the Nmap runner call, excluding XML parsing and database persistence. Prometheus exposes `_bucket`, `_sum`, and `_count` series. |

Labels are bounded: routes use templates, and target IPs, hostnames, request IDs, and job IDs are not labels. Counter-vector series appear after their first observation; a fresh process may not yet expose series for every method, route, status, or job outcome. The Nmap histogram is registered at startup, but its `_count` remains zero until a runner call is observed. Pending/running job gauges are not implemented; the service does not poll PostgreSQL to produce them.

## Start Prometheus

From the repository root, start the Compose stack:

```sh
docker compose up --build -d
```

This also builds and starts the API. Database migrations remain manual; apply `migrations/001_init.up.sql` as described in the README before submitting scans to a fresh database.

- Prometheus UI: <http://localhost:9090>
- API metrics exposition: <http://localhost:8080/metrics>
- Scrape configuration: [prometheus.yml](../prometheus.yml)

## Verify the scrape target

Open <http://localhost:9090/targets>. Find the `nmap-api` target at `api:8080`:

- `UP` means Prometheus can scrape the API.
- `DOWN` means check that the API container is running and that `GET /metrics` responds.

You can also inspect Compose status and logs:

```sh
docker compose ps
docker compose logs --tail=100 api prometheus
```

## Generate metrics

Send an API request. Use a target present in `SCAN_ALLOWED_TARGETS` for scan submissions:

```sh
curl -i -X POST http://localhost:8080/api/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{"targets":["127.0.0.1"],"timeout_seconds":20}'
```

A successful submission returns `202 Accepted`; processing is asynchronous. Once the worker completes or terminally fails a job, its outcome metric is recorded after that terminal state is persisted. Ordinary lease requeues do not increment the failed outcome. Each actual Nmap process call, including one that times out or fails, contributes an execution-duration observation; cancellation before the call completes is still measured for elapsed runner time.

You can create read traffic as well:

```sh
curl 'http://localhost:8080/api/v1/targets/127.0.0.1/scans?limit=5'
```

Remember that the default history response filters its port array to `open` and `closed`; use `state=all` to request every persisted state. This response filter does not affect the worker metrics or stored observations.

## Useful PromQL queries

Enter a query in the Prometheus UI at <http://localhost:9090> and click **Execute**.

| Query | What it shows |
| --- | --- |
| `http_requests_total` | Cumulative HTTP requests by method, route, and status code. |
| `sum(rate(http_requests_total[5m]))` | Approximate total HTTP requests per second over five minutes. |
| `sum by (route) (rate(http_requests_total[5m]))` | Request rate grouped by normalized route. |
| `http_requests_in_flight` | Current in-flight requests by method and normalized route. |
| `scan_jobs_total` | Persisted terminal jobs grouped by outcome. |
| `nmap_execution_duration_seconds_count` | Number of Nmap runner calls observed. |
| `rate(nmap_execution_duration_seconds_sum[5m]) / rate(nmap_execution_duration_seconds_count[5m])` | Average Nmap runner-call duration over five minutes, when samples exist. |
| `histogram_quantile(0.95, sum by (le) (rate(nmap_execution_duration_seconds_bucket[5m])))` | Estimated 95th-percentile Nmap execution duration over five minutes. |

Counters are cumulative and do not reset per request. `rate()` and quantile queries need scrape samples in their selected time window. A newly started Prometheus instance may initially show no samples until a scrape occurs; counters with labels also need matching application activity before their series appear.

## Restart Prometheus and retain metrics

A normal restart preserves the named data volume:

```sh
docker compose restart prometheus
```

The API and PostgreSQL are not restarted by this command.

## Reset Prometheus history only

> **Warning:** This permanently deletes Prometheus time-series history. It does not delete scan history in PostgreSQL. Do not use `docker compose down -v`, which would also remove the PostgreSQL volume.

From the repository root, capture the exact volume mounted at `/prometheus`, stop and remove only the Prometheus container, remove that volume, then recreate the service:

```sh
PROM_CONTAINER="$(docker compose ps -aq prometheus)"
if [ -z "$PROM_CONTAINER" ]; then echo "Prometheus container not found"; exit 1; fi
PROM_VOLUME="$(docker inspect "$PROM_CONTAINER" --format '{{range .Mounts}}{{if eq .Destination "/prometheus"}}{{.Name}}{{end}}{{end}}')"
if [ -z "$PROM_VOLUME" ]; then echo "Prometheus data volume not found; refusing to remove a volume"; exit 1; fi
printf 'About to remove Prometheus volume: %s\n' "$PROM_VOLUME"
docker compose stop prometheus
docker compose rm -f prometheus
docker volume rm "$PROM_VOLUME"
docker compose up -d prometheus
```

This removes only the volume attached to Prometheus at `/prometheus`. Prometheus creates a new volume on startup. Recheck <http://localhost:9090/targets>; the `nmap-api` target should return to `UP` after scraping resumes.

## Rebuild the API after code changes

To build the changed Go code and recreate only the API container while leaving Prometheus and PostgreSQL running:

```sh
docker compose up --build -d --no-deps --force-recreate api
```

Check the new API container with `docker compose ps api` and check its startup logs with `docker compose logs --tail=100 api`. Prometheus keeps its existing history because its volume is unchanged.
