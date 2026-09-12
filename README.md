<h1 align="center">Kabuki</h1>

<div align="center">
<p><em>WAF and CDN analysis — part of the <a href="https://github.com/xwebanalysis">XWA ecosystem</a></em></p>
</div>

<hr>

<p><strong>Status: <em>In development</em></strong> (v0.1.0)</p>

<p>Passive WAF/CDN fingerprinting, bot-challenge analysis, rate-limit profiling and edge mapping with hard anti-blocking guardrails: <strong>Kabuki never tries to bypass or provoke a block</strong>.</p>

## Stack

| Layer | Technology |
|-------|------------|
| Frontend | Angular 22 (standalone, signals, SCSS, Node 24) — Nothing Design System |
| Backend | FastAPI (Python 3.13) + SQLAlchemy 2 + SQLite (PostgreSQL optional) |
| Data contracts | xwa-sdk (shared `Event`/`Error`/`Waf`/`Cdn`/`Challenge`/`RateLimit`) |
| Networking | httpx (single probes) + dnspython (CNAME chains) + stdlib ssl (TLS issuer) |

## Features (current)

- WAF fingerprinting against a 27-vendor signature database (Cloudflare, Akamai, AWS WAF/CloudFront, Imperva, Sucuri, F5, FortiWeb, Barracuda, Fastly/Signal Sciences, Vercel, Netlify, Google Cloud Armor, Azure Front Door, ModSecurity, Wordfence, StackPath, Bunny, KeyCDN, Reblaze, Wallarm, DataDome, HUMAN/PerimeterX, Kasada, Citrix, Radware, Alibaba Cloud, Microsoft) using headers, cookies, body markers and status codes with confidence scoring
- Challenge detection: CAPTCHA, JS challenge, block page and interstitial patterns with relevant headers, response time and conservative bypass indicators
- Rate-limit profiling: `RateLimit-*`, `X-RateLimit-*`, `Retry-After` parsing plus scope, window, threshold estimate and a safe recommended delay
- CDN detection and mapping: header fingerprints, CNAME chain (dnspython), TLS issuer (stdlib ssl) and observed edge nodes (POP codes, cache nodes, IPs); caching behaviour from `CF-Cache-Status`/`X-Cache`/`Age`
- Safe graduated probing: opt-in only (`confirm=true`), default 5 requests (hard cap 20), 500–1500 ms jitter and immediate abort on the first 429/403
- Unified findings (`pass|info|low|medium|high|critical`) in four categories: `waf`, `cdn`, `challenge`, `rate_limit`
- Live progress over WebSocket as xwa-sdk `Event` envelopes (phases `fingerprint`, `challenge`, `rate_limit`, `cdn`), instrument-style terminal in the UI
- Persisted history (list/detail/delete one/delete all) with server-side JSON/CSV export and client-side JSON/CSV/PDF (jsPDF) export
- Optional JWT auth (`KABUKI_JWT_SECRET`) + in-memory rate limiting (`KABUKI_RATE_LIMIT_MAX`, 120/min, `/api/health` exempt)
- Configurable CORS (`XWA_CORS_ORIGINS`) with credentials disabled

## Quick start (local, default)

```bash
./kabuki.sh local all        # backend :8040 (SQLite) + frontend :4240
```

or in two terminals:

```bash
./kabuki.sh local backend    # terminal 1 — FastAPI on :8040 (SQLite)
./kabuki.sh local frontend   # terminal 2 — Angular on :4240
```

- Frontend: http://localhost:4240
- Backend API: http://localhost:8040
- Swagger docs: http://localhost:8040/docs
- SQLite database: `backend/kabuki.db` (WAL, foreign keys, busy timeout 5000 ms)

The script creates/updates `backend/.venv` with `uv` (Python 3.13), installs the
sibling `xwa-sdk` binding in editable mode when available, and falls back to the
git repository documented in `backend/requirements.txt` otherwise.

## Quick start (Docker, PostgreSQL)

```bash
./kabuki.sh docker all       # frontend :4240, backend :8040, PostgreSQL :5452
```

## Anti-blocking policy

Kabuki is designed to observe, not to attack:

- `headers` mode (default) sends **exactly one GET** request per analysis.
- `graduated` mode requires `confirm=true` in the API/UI, is capped at 20
  requests, waits 500–1500 ms (jittered) between probes and aborts on the first
  `429`/`403`. There is no bypass, evasion, credential or session manipulation.
- DNS/TLS phases are passive metadata lookups; no payloads are sent.
- The default User-Agent identifies the tool.

## API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Service info |
| GET | `/api/health` | Health check with real database status (`200`/`503`) |
| POST | `/api/waf/analyze` | Run a WAF/CDN profile (`probe_mode`, `confirm`, `max_requests`) |
| GET | `/api/analyses` | List the 50 most recent analyses |
| GET | `/api/analyses/{id}` | Analysis detail with all sections |
| GET | `/api/analyses/{id}/export?format=json\|csv` | Download an analysis (attachment) |
| DELETE | `/api/analyses/{id}` | Delete one analysis |
| DELETE | `/api/analyses` | Delete all analyses |
| POST | `/api/auth/token` | Issue a JWT (when `KABUKI_JWT_SECRET` is set) |
| WS | `/api/waf/live?target=...` | Stream xwa-sdk `Event`s per phase |

## Documentation

- [docs/README.md](docs/README.md) — documentation index
- [docs/architecture.md](docs/architecture.md) — stack, layout, analysis pipeline and safety model
- [docs/api.md](docs/api.md) — REST and WebSocket API reference
- [docs/development.md](docs/development.md) — execution modes, environment variables, verification

## Roadmap

See [ROADMAP.md](ROADMAP.md) — pending: advanced bypass indicators, full edge IP-range
maps, IP-vs-session scope detection and rule evasiveness work (deliberately out of
scope under the anti-blocking policy).
