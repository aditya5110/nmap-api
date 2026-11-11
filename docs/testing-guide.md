# Nmap API — Testing Guide

This guide covers the regular Go test suite, the PostgreSQL integration tests, and an optional manual API smoke test. Automated PostgreSQL integration tests are repository/database tests; they do not start the API or execute Nmap. The manual smoke test exercises the running API and a real Nmap scan, so use only a target you are authorized to scan.

## Automated Go tests

### Test categories

- **Regular tests** run with `go test ./...`. They cover API handlers, configuration and target validation, service logic, repository behavior with `go-sqlmock`, worker processing, metrics, shutdown, Nmap argument/error/timeout handling, and XML parsing. The runner tests create a temporary fake Nmap executable; parser tests use XML fixtures. These tests do not require PostgreSQL or a real Nmap installation and do not scan a network target.
- **PostgreSQL integration tests** are in `internal/db/repository_integration_test.go`, guarded by `//go:build integration`. They connect to a real PostgreSQL server and exercise the repository against the actual schema, constraints, transactions, locks, and queries. The `integration` tag does not replace the regular tests; running `go test -tags=integration ./...` includes both categories.

Required local tools are Go 1.22 or newer and a running PostgreSQL instance for the integration tests. Docker Compose is optional: any PostgreSQL instance works if it is reachable with the test connection settings below. Nmap, the API service, and a pre-applied migration are not prerequisites.

### Integration database configuration and safety

The test helper reads environment variables directly; Go tests do **not** load `.env`. `DB_PASSWORD` is required. The actual fallbacks are `DB_HOST=localhost`, `DB_PORT=5432`, `DB_USER=appuser`, `DB_NAME=nmapdb`, and `DB_SSLMODE=disable`. A non-default port must be supplied explicitly. The database role must be able to create a schema and drop the schema it owns.

Each integration test creates a cryptographically random, uniquely named schema in `DB_NAME`, configures its database connections to use that schema, and applies `migrations/001_init.up.sql` there. Test fixtures are inserted into this isolated schema. Cleanup drops that schema with `CASCADE` and closes the connection. The tests do **not** truncate or modify tables in the database's normal schema, and you do not need to apply migrations beforehand. If a test process is forcibly terminated, its cleanup may not run; a leftover schema can remain in the configured database.

Use a **dedicated disposable test database**, not the application's development database or a shared database. The commands below start a separate PostgreSQL container without a persistent volume. The sample password is only a local test value—replace it if needed and do not reuse production credentials. If the example container name is already in use, choose a different name rather than deleting an unrelated container.

### Run tests on the host

Run all regular tests (no database required):

```sh
go test ./...
```

Start a dedicated PostgreSQL container. This publishes only the test database on host loopback port `55432` and does not use or reset the Compose development database:

```sh
docker run -d --name nmap-api-test-postgres \
    -e POSTGRES_USER=appuser \
    -e POSTGRES_PASSWORD=integration-test-only \
    -e POSTGRES_DB=nmap_api_test \
    -p 127.0.0.1:55432:5432 \
    postgres:16-alpine

until docker exec nmap-api-test-postgres pg_isready -U appuser -d nmap_api_test >/dev/null 2>&1; do
    sleep 1
done
```

With that container ready, run all PostgreSQL integration tests in the package:

```sh
DB_HOST=127.0.0.1 DB_PORT=55432 DB_USER=appuser \
DB_PASSWORD=integration-test-only DB_NAME=nmap_api_test DB_SSLMODE=disable \
go test -tags=integration ./internal/db -count=1 -v
```

To run one case, change the last command to the following (the test name is an exact match):

```sh
DB_HOST=127.0.0.1 DB_PORT=55432 DB_USER=appuser \
DB_PASSWORD=integration-test-only DB_NAME=nmap_api_test DB_SSLMODE=disable \
go test -tags=integration ./internal/db \
    -run '^TestPostgresConcurrentWorkersClaimDifferentJobs$' -count=1 -v
```

Run every regular and integration test in the repository with:

```sh
DB_HOST=127.0.0.1 DB_PORT=55432 DB_USER=appuser \
DB_PASSWORD=integration-test-only DB_NAME=nmap_api_test DB_SSLMODE=disable \
go test -tags=integration ./... -count=1
```

The `-count=1` flag disables cached results. A successful package run ends with `ok nmap-api/internal/db`; verbose output lists each test as `PASS`. The build tag only enables integration tests—it does not configure or start PostgreSQL.

### Run the integration test runner in Docker

This option runs both the temporary database and Go test runner in containers, on an isolated Docker network. From the repository root:

```sh
set -e
docker network create nmap-api-test
docker run -d --name nmap-api-test-postgres --network nmap-api-test \
    -e POSTGRES_USER=appuser \
    -e POSTGRES_PASSWORD=integration-test-only \
    -e POSTGRES_DB=nmap_api_test \
    postgres:16-alpine

until docker exec nmap-api-test-postgres pg_isready -U appuser -d nmap_api_test >/dev/null 2>&1; do
    sleep 1
done
```

Run the integration tests once PostgreSQL is ready:

```sh
docker run --rm --network nmap-api-test \
    -v "$PWD:/src" -w /src \
    -e DB_HOST=nmap-api-test-postgres -e DB_PORT=5432 \
    -e DB_USER=appuser -e DB_PASSWORD=integration-test-only \
    -e DB_NAME=nmap_api_test -e DB_SSLMODE=disable \
    golang:1.22-alpine \
    go test -tags=integration ./internal/db -count=1 -v
```

If Docker reports that `nmap-api-test-postgres` already exists, do not rerun the creation commands or continue to the test command after that failure. The existing container may not be connected to `nmap-api-test`, which causes the test runner's `no such host` error. First verify it is your disposable test database. If it is, skip `docker network create` and `docker run ... postgres:16-alpine`; connect the existing container to the test network once (skip this if it is already connected):

```sh
docker network connect nmap-api-test nmap-api-test-postgres
```

Then wait for PostgreSQL readiness and run only the integration-test command above. If the existing container is not the intended test database, choose a different container name and use that same name for `--name` and `DB_HOST`; do not remove an unrelated container.

The Go container needs network access to download Go modules unless its module cache is already populated. After the test command completes, clean up only these disposable test resources:

```sh
docker rm -f nmap-api-test-postgres
docker network rm nmap-api-test
```

These commands remove the test-only PostgreSQL container (including its ephemeral data) and test network. They do not remove Compose volumes or application databases. Do not use `docker compose down -v` for test cleanup; it can delete the development PostgreSQL volume.

### Race detector

The race detector can be useful for the Go-level concurrent claim/repository tests as well as the regular suite. It requires a Go-supported platform and a working C toolchain:

```sh
go test -race ./...
DB_HOST=127.0.0.1 DB_PORT=55432 DB_USER=appuser \
DB_PASSWORD=integration-test-only DB_NAME=nmap_api_test DB_SSLMODE=disable \
go test -race -tags=integration ./internal/db -count=1
```

The second command requires the dedicated test PostgreSQL container above to still be running. The race detector checks Go memory races; it does not replace PostgreSQL integration assertions.

After all host-run tests finish, remove only the dedicated test container:

```sh
docker rm -f nmap-api-test-postgres
```

This is destructive to that test container and its ephemeral database only. Do not substitute the Compose PostgreSQL container or remove any named Compose volume.

### PostgreSQL scenarios covered

The integration tests currently verify:

- Transaction rollback for invalid job insertion and duplicate port insertion.
- Presence of required migration indexes and absence of specifically listed indexes.
- `FOR UPDATE SKIP LOCKED` behavior and distinct claims from concurrent claimers.
- Expired-lease retry attempts, terminal failure after the maximum attempts, stale-claim fencing, and aggregate request-status updates across recovery.
- Atomic result replacement without duplicate host/port rows.
- History ordering, limits, empty history, multiple resolved IPs, latest comparable completed scans, and hostname case/trailing-dot matching.

These tests call repository methods using SQL fixtures. They do not test API HTTP/database wiring, execute the application worker pool or Nmap, verify live network scan results, or invoke the service-level port-diff calculation. Unit tests cover handlers/services/workers and Nmap behavior separately; the comparison semantics are tested there, not by these PostgreSQL integration cases. Integration fixtures persist representative port states but do not validate live `open`, `closed`, or `filtered` outcomes. See [project-documentation.md](project-documentation.md#11-testing) for the broader test inventory.

## Manual live-API smoke test

The following optional walkthrough runs an actual scan against an Ubuntu VM. It is not a substitute for the automated PostgreSQL integration tests, and its outcomes depend on network reachability and Nmap observations.

## 1. Start the Ubuntu Virtual Machine

1.  Open your virtualization platform (VirtualBox, VMware, UTM, cloud
    console, etc.).
2.  Select your Ubuntu virtual machine.
3.  Click **Start** or **Power On**.
4.  Wait for Ubuntu to boot.
5.  Log in to the Ubuntu VM.

Make sure the VM is connected to a network that allows your API
container to reach it.

## 2. Find the Ubuntu VM's IP Address

Open a terminal inside Ubuntu and run:

``` bash
hostname -I
```

This displays the IP addresses assigned to the VM.

Alternatively, use:

``` bash
ip -4 addr show
```

Identify the IPv4 address associated with the active network interface.

For example:

``` text
192.168.x.x
```

Use the actual IP address of your VM wherever `<UBUNTU_MACHINE_IP>`
appears in the commands and Postman URLs below.

**Important:** The VM must be reachable from the machine or Docker
container running the Nmap API. If the API runs inside Docker, verify
connectivity from the API container as well.

## 3. Optional: Clear scan data for a fresh-start manual test (destructive)

> **Warning:** This permanently deletes every scan request, job, result, and
> port row in the selected database and resets their auto-incrementing IDs.
> Run it only against a disposable local database whose data you intend to
> discard. Do not run it against a shared, production, or valuable
> development database. This step is not needed for the PostgreSQL
> integration tests above; they create and remove their own isolated schema.

With the default Compose database credentials, run this from the project
directory:

```sh
docker compose exec postgres psql -U appuser -d nmapdb -c "TRUNCATE TABLE scan_ports, scan_results, scan_jobs, scan_requests RESTART IDENTITY CASCADE;"
```

This leaves the table definitions intact but deletes all rows from the four
scan tables. If `DB_USER` or `DB_NAME` differs in `.env`, substitute the
configured values. If you do not specifically need an empty history, skip
this step. For a fresh Compose database, apply the initial migration once as
documented in the [README](../README.md#build-and-run-with-docker-compose).

## 4. Rebuild and Restart the API

Whenever you make changes to the API code, rebuild and restart the API
service:

``` bash
docker compose up --build -d api
```

Verify that the API container is running:

``` bash
docker compose ps api
```

Check that the container is up and running.

If Prometheus is running, it will resume scraping the rebuilt API at `api:8080`. Its history remains in the `prometheus_data` volume.

## 5. Start an HTTP Server on Ubuntu

Open a terminal inside the Ubuntu VM and start a simple HTTP server on
port `8080`:

``` bash
python3 -m http.server 8080 --bind 0.0.0.0
```

Keep this terminal running while performing the first scan.

The server listens on all network interfaces, allowing connections from
other machines that can reach the VM.

## 6. Submit the First Scan Request

Open Postman and send the following request.

**Method:** `POST`

**URL:**

``` text
http://localhost:8080/api/v1/scans
```

**Body:** Select `raw` → `JSON` and provide:

``` json
{
  "targets": ["<UBUNTU_MACHINE_IP>"],
  "timeout_seconds": 60
}
```

Replace `<UBUNTU_MACHINE_IP>` with the actual IP address obtained in
Step 2.

Before starting the API, add that exact IP address to `SCAN_ALLOWED_TARGETS`
in `.env` (or its environment). The configuration loader validates and
normalizes allowlist entries at startup; malformed entries prevent the API
from starting. The API does not perform DNS lookup as part of target
validation.

Click **Send** to submit the scan request.

## 7. Verify Scan History

After the scan completes, send the following GET request in Postman.

**Method:** `GET`

**URL:**

``` text
http://localhost:8080/api/v1/targets/<UBUNTU_MACHINE_IP>/scans?limit=5
```

The default `/scans` response shows only open and closed ports. Use `?limit=5&state=all` to inspect filtered ports too, or `?limit=5&state=filtered` to show only filtered observations.

Verify that the scan appears in the response. If Nmap includes port `8080`
in its output, its observed state is shown; reachability and filtering mean
that `open` is not guaranteed. Use `state=all` to see filtered observations.

## 8. Stop the HTTP Server on Ubuntu

Go back to the Ubuntu terminal where the HTTP server is running and
press:

``` text
Ctrl + C
```

This stops the HTTP server.

## 9. Verify That Port 8080 Is No Longer Listening

Run the following command on Ubuntu:

``` bash
sudo ss -lntp | grep 8080
```

Verify that there is no output, indicating that nothing is listening on
port `8080`.

## 10. Submit the Second Scan Request

Return to Postman and submit the same POST request again.

**Method:** `POST`

**URL:**

``` text
http://localhost:8080/api/v1/scans
```

**Body:**

``` json
{
  "targets": ["<UBUNTU_MACHINE_IP>"],
  "timeout_seconds": 60
}
```

This creates another scan after the HTTP server has been stopped.

## 11. Verify the Second Scan

Send the GET request again with `state=all` so the response includes filtered observations as well as open/closed ports.

**Method:** `GET`

**URL:**

``` text
http://localhost:8080/api/v1/targets/<UBUNTU_MACHINE_IP>/scans?limit=5&state=all
```

Check the scan history and compare the results of the two scans.

## 12. Verify Port Changes Between Scans

Finally, send the following GET request in Postman.

**Method:** `GET`

**URL:**

``` text
http://localhost:8080/api/v1/targets/<UBUNTU_MACHINE_IP>/changes
```

The endpoint compares all persisted states and does not use the `/scans`
state filter. A comparable pair must be completed and have the same
resolved-IP set; hosts must be reported `up` in both scans to contribute
port comparisons. If Nmap does not report an individual port entry or an
exact port membership in `<extraports>` reasons, the API preserves the
missing observation rather than guessing its state. A missing port may
appear as removed with its prior state; the API does not infer `closed`.
The second scan may show `closed`, `filtered`, another reported state, or
no observation, depending on network conditions and Nmap output.

------------------------------------------------------------------------

## Expected Test Flow

1. **Start Ubuntu VM** — The VM boots successfully.
2. **Obtain VM IP address** — Identify the VM's IP address.
3. **Prepare the database** — Apply the migration only if required. The optional reset in Step 3 above is destructive and only for a disposable database.
4. **Rebuild API** — The latest API code is running with the target in its allowlist.
5. **Start Ubuntu HTTP server** — Port `8080` is listening.
6. **Submit first scan** — The request is accepted and queued.
7. **Check scan history** — Inspect the recorded observations; an open result is not guaranteed.
8. **Stop HTTP server** — The HTTP server stops.
9. **Check port 8080** — Nothing should be listening on port `8080`.
10. **Submit second scan** — The request is accepted and queued.
11. **Check scan history** — Both scans may appear after processing completes.
12. **Check changes endpoint** — A diff is available only if a comparable completed pair exists.

## Important Notes

- The API must be running before submitting requests through Postman.
- The Ubuntu VM must remain powered on during both scans.
- Use the same VM IP address for both scans so the API can compare the results for the same target.
- The API container must be able to reach the Ubuntu VM over the network.
- Nmap may report port `8080` as **closed**, **filtered**, another state, or omit it, depending on selected ports, network conditions, and XML observations.
- A **filtered** result does not necessarily mean the port is closed. It means Nmap cannot determine whether the port is open or closed because network filtering may be interfering with its probes or responses.
- No database reset is required. The optional Step 3 reset is destructive and must only be used with a disposable database. Removing a PostgreSQL container or volume is also destructive; only remove resources created specifically for a disposable test database.
