# Architecture

## Overview

Kabuki is a two-tier web application: an Angular single-page application and a FastAPI service. The backend owns the analysis pipeline and persistence; the frontend renders the WAF/CDN profile and streams live progress.

```
+--------------------+      HTTP/JSON       +---------------------------+
| Angular 22 SPA     | -------------------> | FastAPI (uvicorn)          |
| (localhost:4240)   | <------------------- | (localhost:8040)           |
+--------------------+    WebSocket        +--------------+-------------+
                                                    |     |
                                                    v     v
                                              SQLite (default) / PostgreSQL
```

## Backend

Layout:

```
backend/
├── app/
│   ├── __init__.py
│   ├── analyzer.py      # WAF/CDN signatures, challenges, rate limits, guardrails
│   ├── database.py      # engine setup, SQLite/PostgreSQL switch, ping, PRAGMAs
│   ├── events.py        # xwa-sdk Event envelope helpers (SDK + fallback)
│   ├── main.py          # FastAPI app, REST routes, WebSocket endpoint
│   ├── models.py        # SQLAlchemy ORM models
│   ├── schemas.py       # Pydantic v2 request/response models
│   └── security.py      # CORS config, optional JWT auth, rate limiting
├── tests/               # analyzer unit tests + API integration tests (MockTransport)
├── Dockerfile           # python:3.13-slim (PostgreSQL mode)
├── requirements.txt             # runtime (SQLite by default)
├── requirements-postgres.txt    # + psycopg2-binary (docker mode)
└── requirements-dev.txt         # + pytest/anyio (tests)
```

### Components

- **analyzer.py** — the analysis core:
  - `WAF_SIGNATURES`: 27 vendor signatures built from header rules (`HeaderRule`, prefix match supported), cookie patterns, body patterns and blocked status codes. Each match carries confidence (`high|medium|low`), detection method (`header|cookie|body`) and raw evidence.
  - `CDN_SIGNATURES`: 14 providers with edge-node and caching header sets; `detect_cdn()` also accepts a TLS issuer hint.
  - `detect_challenges()` classifies CAPTCHA / `js_challenge` / `block_page` / `interstitial` responses. On informational 200 responses only concrete artifacts (reCAPTCHA/hCaptcha/Turnstile/CF challenge markers), a strong interstitial phrase or ≥2 block markers qualify, so marketing pages that merely mention "captcha" are ignored.
  - `parse_rate_limit()` merges `RateLimit-*`, `X-RateLimit-*` and `Retry-After` from every probe (the aborting 429 included) and derives scope, threshold estimate and a conservative `recommended_delay_ms`.
  - `resolve_dns_chain()` (dnspython) and `inspect_tls_issuer()` (stdlib `ssl` in a worker thread) are best-effort and never fatal.
  - `analyze_target()` orchestrates the four phases (`fingerprint`, `challenge`, `rate_limit`, `cdn`) and accepts an optional async progress callback used by the WebSocket endpoint. It also accepts an `httpx` transport for hermetic tests.
- **models.py** — six tables: `analyses`, `findings`, `waf_detections`, `cdn_observations`, `challenges` and `rate_limit_observations`. All children cascade on delete; JSON payloads (evidence, headers, edge nodes, bypass indicators) are stored as TEXT.
- **database.py** — SQLite by default (`DB_DRIVER=sqlite`, path `DB_PATH`) or PostgreSQL (`DB_DRIVER=postgresql`). SQLite connections enable `foreign_keys`, `journal_mode=WAL` and `busy_timeout=5000`.
- **security.py** — `cors_settings()` builds the CORSMiddleware arguments from `XWA_CORS_ORIGINS` (localhost/LAN regex by default, credentials disabled), `auth_middleware` enforces an optional HS256 Bearer token, `rate_limit_middleware` implements a 120 req/min sliding window (`/api/health` exempt), and `validate_ws_token()` guards WebSockets via `?token=`.
- **events.py** — builds xwa-sdk `Event` envelopes through the SDK dataclasses when installed, with a structurally identical dict fallback. The `EventEmitter` guarantees monotonic `seq` and a bound persisted `analysis_id`.
- **main.py** — REST routes, WebSocket, global exception handlers that convert `HTTPException`/validation errors into the xwa-sdk `Error` envelope, and lifespan schema creation.

### Analysis pipeline

1. `POST /api/waf/analyze` persists an `Analysis` row with status `RUNNING`.
2. **fingerprint**: one GET (headers mode) fingerprints WAF signatures. Graduated mode (opt-in) sends up to `max_requests` probes with 500–1500 ms jitter and aborts on the first 429/403.
3. **challenge**: challenge patterns are classified from status, body markers and headers; response time and conservative indicators are stored.
4. **rate_limit**: headers from all probes are parsed into scope, limit, window, threshold estimate and recommended delay.
5. **cdn**: the DNS CNAME chain, TLS issuer and response headers are combined into a CDN observation with edge nodes and caching status.
6. Unified findings are generated for every section (including "absent" findings), persisted and returned with counts. Status becomes `COMPLETED` (or `ERROR` with the message stored and a 400/502 envelope returned).

The WebSocket variant (`/api/waf/live`) persists the analysis first and
streams xwa-sdk `Event` envelopes with the **persisted id** as `analysis_id`
(string), monotonic `seq` and UTC `ts`: `analysis_started`,
`analysis_progress` per phase, `item_found` per section entry and finding, then
`analysis_completed`/`analysis_error`.

### Safety model (anti-blocking)

Kabuki is deliberately non-offensive:

- `headers` mode sends exactly one GET request; that is the default everywhere.
- `graduated` mode is refused with HTTP 400 unless `confirm=true`; the request
  count is capped at 20 and the loop stops immediately on `429`/`403` without
  retrying.
- No evasion payloads, no session/credential manipulation, no subprocesses.
- DNS and TLS phases only read metadata.
- The default User-Agent identifies the tool:
  `Mozilla/5.0 (compatible; Kabuki/0.1; +https://github.com/xwebanalysis/kabuki) WAF-CDN-analyzer`.

## Frontend

Layout:

```
frontend/
├── src/
│   ├── app/
│   │   ├── core/               # api.service, live.service, theme.service, i18n.service, export.service
│   │   ├── shared/             # terminal, metric-card, status-badge, export-actions
│   │   ├── features/           # analyzer, results, history
│   │   ├── app.config.ts       # providers (router, HttpClient)
│   │   ├── app.routes.ts       # '' analyzer, /analysis/:id results, /history
│   │   ├── app.ts / app.html   # shell: nav, health, theme + locale toggles
│   │   └── app.scss
│   ├── environments/
│   │   └── environment.ts      # apiBaseUrl / wsBaseUrl (host resolved at runtime)
│   ├── _fonts.scss             # @font-face for self-hosted woff2
│   ├── styles.scss             # Nothing Design tokens (+ --gold) and primitives
│   └── index.html
├── public/fonts/               # Doto, Space Grotesk, Space Mono woff2 (latin)
├── public/favicon.ico          # dot-matrix ICO
├── scripts/test.sh             # maps `npm test -- --run` onto the Angular builder
├── Dockerfile                  # node:24 (dev server)
└── package.json                # Angular 22.1 + jsPDF 4 (lazy chunk)
```

- The analyzer feature offers REST (`ANALYZE`) and live (`LIVE STREAM`) runs,
  a segmented control for `headers`/`graduated`, a confirm switch for graduated
  probing and a max-requests field. Graduated runs are blocked in the UI when
  the switch is off (the backend enforces the same rule with a 400).
- The terminal renders phase progress and `item_found` lines; phase chips show
  `pending/running/done`.
- Results render hero finding count, four metric cards and dense tables for WAF,
  CDN, challenges, rate limit and findings. `[LOADING...]`/`[ERROR: ...]` are
  inline, never toasts.
- Exports: client-side JSON/CSV/PDF (jsPDF is dynamically imported) and
  server-side `format=json|csv` links.
- `ApiService` reads `environment.apiBaseUrl` / `environment.wsBaseUrl`; only
  the port (8040) is fixed, the hostname is resolved at runtime so localhost and
  LAN access both work.

## Data contracts

REST errors use the xwa-sdk `Error` envelope. Live stream events conform to the
xwa-sdk `Event` schema (`seq`, `type`, `tool`, `analysis_id`, `ts`, `payload`).
Persisted sections map to the xwa-sdk items `Waf`, `Cdn`, `Challenge`,
`RateLimit` and `Finding`. The backend consumes the `xwa-sdk` Python package
installed local-first by `kabuki.sh` (editable sibling repo) with the git
fallback documented in `requirements.txt`.
