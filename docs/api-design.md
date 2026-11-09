# API design and implemented behavior

This document describes the API that is implemented in the current repository. The endpoints are intentionally small: submit scan work, retrieve target history, and compare comparable scans. Scan submissions are asynchronous. There is no request-status endpoint.

One submitted target creates one logical job. If Nmap returns multiple distinct IPv4/IPv6 addresses for a hostname, the job can store one host result per resolved IP.

## 1. Endpoints

- `POST /api/v1/scans`
- `GET /api/v1/targets/{target}/scans`
- `GET /api/v1/targets/{target}/changes`

All responses use JSON. Unsupported methods return `405 Method Not Allowed` with an `Allow` header. Unknown paths return `404 Not Found`.

## 2. Submit scans — `POST /api/v1/scans`

The handler accepts a JSON request, validates the entire batch, and persists one request plus one pending job for each target in a transaction. It returns after this transaction commits; the workers run Nmap later.

Request example (targets must be in `SCAN_ALLOWED_TARGETS`):

```json
{
  "targets": ["127.0.0.1", "::1"],
  "timeout_seconds": 60
}
```

`timeout_seconds` is optional and defaults to `DEFAULT_TIMEOUT_SECONDS`; it must be from 1 through 120 seconds. `targets` must contain at least one entry and cannot exceed `MAX_BATCH_SIZE`.

Successful response (`202 Accepted`):

```json
{
  "request_id": "6e0aa93a-4d0a-45ac-8ff0-ace0e1480e2c",
  "status": "accepted",
  "targets": [
    {"target": "127.0.0.1", "status": "pending"},
    {"target": "::1", "status": "pending"}
  ]
}
```

The returned `accepted` status describes successful queueing; the individual targets start as `pending`. It does not mean Nmap has completed.

Validation errors return `400 Bad Request`. For example:

```json
{
  "error": {
    "code": "INVALID_TARGET",
    "message": "target \"bad!host\" is not a valid IPv4 address, IPv6 address, or hostname"
  }
}
```

Other implemented validation codes include `INVALID_JSON`, `INVALID_REQUEST`, `BATCH_TOO_LARGE`, `INVALID_TIMEOUT`, and `TARGET_NOT_ALLOWED`. The body is limited to 1 MiB, unknown JSON fields are rejected, and exactly one JSON value is required. All targets are validated before persistence, so one bad or disallowed target rejects the complete batch.

## 3. Recent history — `GET /api/v1/targets/{target}/scans`

Returns recent jobs matching the submitted hostname or resolved IP, newest first. The optional `limit` query parameter defaults to 20 and must be an integer from 1 through 100. No matching history returns `200 OK` with an empty `scans` array; it does not return 404.

Example: `GET /api/v1/targets/127.0.0.1/scans?limit=10`

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
        {
          "resolved_ip": "127.0.0.1",
          "port": 80,
          "protocol": "tcp",
          "state": "open",
          "service": "http",
          "reason": "syn-ack"
        }
      ]
    }
  ]
}
```

The `ports` array contains only observations returned by Nmap. `service` may be `null`; `reason` is omitted if absent. Timestamps are `null` until set. History includes jobs that have not completed, so their observations can be empty. Invalid targets and invalid limits return `400 Bad Request`; database errors return `500 Internal Server Error`.

An invalid limit example:

```json
{"error":{"code":"INVALID_LIMIT","message":"limit must be between 1 and 100"}}
```

## 4. Compare scans — `GET /api/v1/targets/{target}/changes`

The repository finds the latest pair of completed scans that have non-null start/finish times and the same resolved-IP set. It need not compare the two latest completed scans overall if their resolved IP sets differ. Ports are matched by resolved IP, protocol, and port number. A state or service difference for a matching identity is reported as changed.

Example: `GET /api/v1/targets/127.0.0.1/changes`

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

Each `added_ports` or `removed_ports` entry includes `resolved_ip`, `port`, `protocol`, `state`, and `service` (possibly `null`). No comparable pair returns `404 Not Found`:

```json
{"error":{"code":"NO_COMPARABLE_SCANS","message":"fewer than two comparable completed scans are available"}}
```

The comparison includes only IP addresses marked `up` in both selected scans. Nmap states such as `open`, `closed`, `filtered`, and combined states are preserved as reported. A port identity absent from the current output is reported as removed with its previous state; the API does not claim that it is now closed. Missing observations are not reliable proof of a firewall change.

## 5. Target validation and allowlist

The scan service accepts IPv4, IPv6, or ASCII hostnames. It rejects empty values, surrounding whitespace, malformed IPv4-looking strings, invalid hostname characters, empty labels, labels longer than 63 characters, and hostnames longer than 253 characters. Hostname labels cannot begin or end with `-`.

Each submitted target must also match an exact entry in `SCAN_ALLOWED_TARGETS`; an empty/unset allowlist denies all scan submissions. IPv4/IPv6 values are normalized for allowlist comparison. Hostnames are lowercased and a trailing dot is removed for comparison. Wildcards and CIDR ranges are not implemented. The original submitted target is stored on the job. No DNS lookup occurs during request validation; Nmap resolves hostnames during asynchronous execution, so a valid but unresolvable name can receive `202` and later fail during processing.

History and changes validate target syntax but do not require the scan allowlist.

## 6. Error handling and status codes

All error responses have this shape:

```json
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "at least one target is required"
  }
}
```

Implemented status behavior:

- `200 OK`: history or changes returned successfully. Empty history is an empty array.
- `202 Accepted`: request and target jobs have been persisted; scanning is asynchronous.
- `400 Bad Request`: invalid JSON, target, timeout, batch size, allowlist membership, or history limit.
- `404 Not Found`: unknown endpoint or fewer than two comparable completed scans for changes.
- `405 Method Not Allowed`: method is unsupported for a known endpoint; `Allow` indicates the supported method.
- `500 Internal Server Error`: unexpected persistence/read failure; response is generic and details are logged.

There is no `429 Too Many Requests` response or queue-overload admission control in the current implementation.

## 7. Asynchronous processing outline

The API validates every member of the batch and transactionally stores the request and all jobs before returning `202`. A bounded worker pool claims jobs from PostgreSQL with `FOR UPDATE SKIP LOCKED`, executes the fixed Nmap profile, parses XML, and stores results. Each target has an independent outcome, so a failed scan does not cancel sibling jobs. The request's aggregate status is updated in PostgreSQL, but no endpoint exposes it directly. See [architecture.md](architecture.md) for claiming, leases, recovery, schema, and proposed scaling details.

## 8. Scope and non-features

The current API does not provide a request-status endpoint, scan-profile selection, UDP scanning, custom port ranges, authentication, rate limiting, metrics endpoints, or a distributed queue. The API does not inspect or change firewall rules. Nmap results are observations from the scanner's network location using the fixed top-1,000 TCP port profile.
