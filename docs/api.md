# API Reference

Base URL (local): `http://localhost:8040`. OpenAPI/Swagger UI: `http://localhost:8040/docs`.

## Conventions

- Responses use JSON. Timestamps in events are UTC ISO-8601 (`Z`/`+00:00`).
- Errors follow the xwa-sdk `Error` envelope:

```json
{
  "error": {
    "code": "UPSTREAM_ERROR",
    "message": "Failed to fetch target: ...",
    "detail": null,
    "retryable": true
  }
}
```

| Status | Code | Condition |
|--------|------|-----------|
| `400` | `BAD_REQUEST` | Invalid target, unsupported probe mode or graduated without `confirm=true` |
| `401` | `UNAUTHORIZED` | Bearer token missing/invalid (only when auth is enabled) |
| `404` | `NOT_FOUND` | Analysis does not exist |
| `422` | `VALIDATION_ERROR` | Request/query validation failed (e.g. `max_requests > 20`) |
| `429` | `RATE_LIMITED` | API rate limit exceeded (default 120 req/min per IP; `/api/health` exempt) |
| `502` | `UPSTREAM_ERROR` | Target fetch failed (DNS, TLS, connection, timeout) |
| `503` | `SERVICE_UNAVAILABLE` | Database not reachable (`/api/health`) |

CORS is configurable through `XWA_CORS_ORIGINS` (comma-separated origins); when
unset, localhost and private LAN ranges are allowed. Credentials are disabled —
use `Authorization: Bearer`.

## REST

### GET /

Service information.

```json
{ "status": "ok", "service": "kabuki", "version": "0.1.0" }
```

### GET /api/health

Health check including real database connectivity. Returns `200` when the
database answers and `503` otherwise.

```json
{ "status": "ok", "database": "ok", "version": "0.1.0", "tool": "kabuki" }
```

### POST /api/waf/analyze

Runs a WAF/CDN profile and persists the results.

Request:

```json
{
  "target": "https://example.com",
  "probe_mode": "headers",
  "confirm": false,
  "max_requests": 5
}
```

- `target` — domain or full URL. A missing scheme is completed with `https://`.
- `probe_mode` — `headers` (default, exactly one GET) or `graduated`
  (opt-in profiling).
- `confirm` — required `true` for `graduated`; otherwise the request is refused
  with `400` and no network probe is performed.
- `max_requests` — 1..20 (default 5), only meaningful in graduated mode.

Response `200 OK` (abridged):

```json
{
  "analysis": {
    "id": 1,
    "target": "https://example.com",
    "status": "COMPLETED",
    "analysis_type": "waf_profile",
    "created_at": "2026-09-12T10:00:00",
    "findings": [
      {
        "id": 1,
        "tool": "kabuki",
        "severity": "info",
        "category": "waf",
        "check": "waf.fingerprint",
        "title": "WAF detected: Cloudflare / Cloudflare WAF",
        "description": "...",
        "evidence": "{\"vendor\": \"Cloudflare\", ...}",
        "confidence": "high"
      }
    ],
    "waf_detections": [
      {
        "id": 1,
        "vendor": "Cloudflare",
        "product": "Cloudflare WAF",
        "confidence": "high",
        "detection_method": "header",
        "evidence": "server: cloudflare | cf-ray: ...",
        "blocked": false
      }
    ],
    "cdn_observations": [
      {
        "id": 1,
        "provider": "Cloudflare",
        "edge_nodes": "[\"pop:MAD\", \"203.0.113.7\"]",
        "origin_hidden": false,
        "caching": "hit",
        "evidence": "cf-ray: ..."
      }
    ],
    "challenges": [],
    "rate_limit_observations": [
      {
        "id": 1,
        "scope": "unknown",
        "limit": null,
        "window_seconds": null,
        "headers": "{}",
        "threshold_estimate": null,
        "recommended_delay_ms": 2000
      }
    ]
  },
  "finding_count": 3,
  "waf_count": 1,
  "cdn_count": 1,
  "challenge_count": 0,
  "rate_limit_count": 1,
  "guardrail": {
    "probe_mode": "headers",
    "max_requests": 5,
    "requests_sent": 1,
    "aborted": false,
    "abort_reason": null,
    "delay_ms_min": 500,
    "delay_ms_max": 1500
  }
}
```

On fetch failure the analysis is stored with status `ERROR` and the request
returns `502`. Graduated without `confirm` returns `400` and the refused
analysis is still visible in history with status `ERROR`.

### GET /api/analyses

Lists the 50 most recent analyses (newest first).

```json
[
  {
    "id": 1,
    "target": "https://example.com",
    "status": "COMPLETED",
    "analysis_type": "waf_profile",
    "created_at": "2026-09-12T10:00:00",
    "finding_count": 3,
    "waf_count": 1,
    "cdn_count": 1,
    "challenge_count": 0,
    "rate_limit_count": 1
  }
]
```

### GET /api/analyses/{id}

Full analysis detail. JSON payload fields (`evidence`, `headers`, `edge_nodes`,
`bypass_indicators`) are returned as JSON strings inside the model. `404` when
not found.

### GET /api/analyses/{id}/export?format=json|csv

Downloadable export with `Content-Disposition: attachment`:

- `format=json` (default) — full document with parsed JSON fields;
  `kabuki-analysis-<id>.json`.
- `format=csv` — one row per record (`finding`, `waf_detection`,
  `cdn_observation`, `challenge`, `rate_limit`); `kabuki-analysis-<id>.csv`.

Any other `format` value returns `422`. `404` when not found.

### DELETE /api/analyses/{id}

Deletes one analysis and all its sections. Returns `204`; `404` when not found.

### DELETE /api/analyses

Deletes all analyses. Returns `204`.

### POST /api/auth/token

Issues a signed JWT (HS256). Only available when `KABUKI_JWT_SECRET` is set;
returns `403` when auth is disabled.

```json
{ "password": "..." }
```

Response `200 OK`:

```json
{ "token": "<jwt>", "expires_in": 86400 }
```

## WebSocket

### WS /api/waf/live?target=...&probe_mode=...&confirm=...&max_requests=...

Persists the analysis and streams progress. Query parameters: `target`
(required), `probe_mode` (`headers` default), `confirm` (required for
graduated), `max_requests` (default 5) and `token` (required only when
`KABUKI_JWT_SECRET` is set — WebSocket clients cannot send headers).

Every message is an xwa-sdk `Event` envelope. `analysis_id` is the **persisted
analysis id serialized as a string** (never the target), `seq` starts at 1 and
is monotonic, and `ts` is UTC ISO-8601.

```json
{
  "seq": 2,
  "type": "analysis_progress",
  "tool": "kabuki",
  "analysis_id": "42",
  "ts": "2026-09-12T10:00:00.123456+00:00",
  "payload": { "phase": "fingerprint", "message": "Probing example.com (headers mode)" }
}
```

| type | payload |
|------|---------|
| `analysis_started` | `{ "target": ..., "probe_mode": ..., "max_requests": ... }` |
| `analysis_progress` | `{ "phase": "fingerprint\|challenge\|rate_limit\|cdn", "message": ..., "data"?: ... }` (two per phase: start + result) |
| `item_found` | one per WAF detection, CDN observation, challenge, rate-limit profile and finding |
| `analysis_completed` | `{ "summary": { "finding_count", "waf_count", "cdn_count", "challenge_count", "rate_limit_count" }, "guardrail": ..., "status_code": ..., "blocked": ... }` |
| `analysis_error` | xwa-sdk `Error` shape (`{ "code": "TARGET_ERROR", "message": ..., "retryable": true }`) |

On a refused request (graduated without confirm, invalid target) the analysis is
marked `ERROR` and a terminal `analysis_error` with code `INVALID_REQUEST` is
sent. If the client disconnects mid-run the analysis is marked `CANCELLED`.

## Authentication and rate limiting

- When `KABUKI_JWT_SECRET` is set, every `/api/*` route except `/`,
  `/api/health` and `/api/auth/token` requires `Authorization: Bearer <token>`
  (HS256, 24 h). When unset (default) the API is open.
- All non-exempt routes share an in-memory sliding window:
  `KABUKI_RATE_LIMIT_MAX` requests per client IP per 60 s (default `120`).
