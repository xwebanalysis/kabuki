# Development

## Requirements

| Component | Requirement |
|-----------|-------------|
| Node.js | >= 24.15 (Angular 22 CLI minimum) |
| Python | 3.13 (managed with `uv`); the Docker image uses 3.13 |
| uv | `~/.local/bin/uv` (used to create the venv and install packages) |
| Docker | optional — only for the compose mode |
| Database | none for local mode (SQLite); PostgreSQL 17 for docker mode |

## Execution modes

`kabuki.sh` is the entry point. `local` is the default:

| Command | Description |
|---------|-------------|
| `./kabuki.sh` | Same as `./kabuki.sh local all` |
| `./kabuki.sh local all` | Native backend :8040 (SQLite) + frontend :4240 |
| `./kabuki.sh local backend` | Backend only, foreground |
| `./kabuki.sh local frontend` | Frontend only |
| `./kabuki.sh docker all` | Full stack on :4240/:8040 plus PostgreSQL 17 on :5452 |
| `./kabuki.sh docker backend` | Backend plus its `depends_on` service (PostgreSQL) |
| `./kabuki.sh docker frontend` | Frontend only |

Legacy aliases `--sqlite`, `--native` and `--fast` are accepted as `local`.

The `local` mode:

1. Creates/updates `backend/.venv` with `uv venv --python 3.13 --seed`.
2. Installs `requirements-dev.txt` (runtime + pytest/anyio).
3. Installs the sibling `xwa-sdk` binding in editable mode when
   `/home/x/Documents/xwebanalysis/xwa-sdk/bindings/python` exists; otherwise
   falls back to the git spec documented in `requirements.txt`.
4. Starts uvicorn on :8040 with `DB_DRIVER=sqlite`, waits for `/api/health`,
   then starts Angular on :4240.

Manual equivalents:

```bash
# backend (native, SQLite)
cd backend
~/.local/bin/uv venv --python 3.13 --seed .venv
~/.local/bin/uv pip install --python .venv/bin/python -r requirements-dev.txt
~/.local/bin/uv pip install --python .venv/bin/python -e ../../xwa-sdk/bindings/python
export DB_DRIVER=sqlite DB_PATH=./kabuki.db
.venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8040 --reload

# frontend (native)
cd frontend
npm ci
npm start                        # ng serve --host 0.0.0.0, port 4240 (angular.json)
```

## Environment variables (backend)

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_DRIVER` | `sqlite` | `sqlite` or `postgresql` |
| `DB_PATH` | `./kabuki.db` | SQLite database file (used when `DB_DRIVER=sqlite`) |
| `DB_HOST` | `db` | PostgreSQL host |
| `DB_NAME` | `kabuki` | PostgreSQL database name |
| `DB_USER` | `postgres` | PostgreSQL user |
| `DB_PASS` | `postgres` | PostgreSQL password |
| `XWA_CORS_ORIGINS` | unset | Comma-separated allowed origins; unset = localhost + LAN regex |
| `KABUKI_JWT_SECRET` | unset | When set, all `/api/*` routes require an HS256 Bearer token |
| `KABUKI_AUTH_PASSWORD` | `kabuki` | Password accepted by `POST /api/auth/token` |
| `KABUKI_RATE_LIMIT_MAX` | `120` | Requests per client IP per 60 s window (`XWA_RATE_LIMIT_MAX` also accepted) |

`kabuki.sh` also honors `KABUKI_BACKEND_PORT`, `KABUKI_FRONTEND_PORT`, `KABUKI_DB_PATH` and `XWA_SDK_DIR`.

Example with auth enabled:

```bash
export KABUKI_JWT_SECRET=change-me-to-at-least-32-bytes-long
export KABUKI_AUTH_PASSWORD=change-me
./kabuki.sh local backend
# obtain a token:
curl -X POST http://localhost:8040/api/auth/token \
  -H 'Content-Type: application/json' -d '{"password":"change-me"}'
# use it:
curl -H 'Authorization: Bearer <token>' http://localhost:8040/api/analyses
# WebSocket (token in the query string):
#   ws://localhost:8040/api/waf/live?target=https://example.com&token=<token>
```

## Tests and verification

```bash
# backend tests (isolated SQLite temp DB, httpx.MockTransport, no network)
cd backend
.venv/bin/python -m pytest -q

# smoke test
.venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8040 &
curl -s http://localhost:8040/api/health
# local target (python -m http.server 8099) to avoid touching external hosts:
curl -s -X POST http://localhost:8040/api/waf/analyze \
  -H 'Content-Type: application/json' -d '{"target":"http://127.0.0.1:8099"}'
curl -s http://localhost:8040/api/analyses
curl -sD - -o /dev/null "http://localhost:8040/api/analyses/1/export?format=csv"

# frontend
cd frontend
npm ci
npm test              # vitest via the Angular builder (scripts/test.sh adds --watch=false)
npm run build
```

Test suites:

- `tests/test_analyzer.py` — signature database (positive/negative cases),
  challenge classification, rate-limit parsing, DNS chain, CDN detection and
  guardrail enforcement (graduated requires confirm, cap, single probe).
- `tests/test_api.py` — health, analyze with `httpx.MockTransport` fixtures
  (clean/Cloudflare/Imperva/rate-limit), graduated without confirm → 400,
  graduated abort on 429, error envelopes, exports, CRUD and the WebSocket
  event shape (`analysis_id` persisted, phases, seq, UTC ts).
- Frontend specs — `ApiService` HTTP methods and URL builders, export component,
  analyzer state (blocked graduated, REST, live events, error events) and shell.

## Fonts

The woff2 files in `frontend/public/fonts/` were downloaded from Google Fonts
with a Chrome User-Agent and are declared in `frontend/src/_fonts.scss`. To
refresh them, re-run the documented curl + parse flow in
`docs/architecture.md`; if the download is not possible, replace the `@use
'fonts';` line with the Google Fonts `<link>` shown in `src/index.html`.

## Cleanup

```bash
./clean.sh
```

Stops compose services (with volumes) and removes the venv, the SQLite file
(plus `-wal`/`-shm`), `node_modules`, `dist`, `.angular` and caches.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| Frontend shows "backend offline" | Backend not running on :8040, or the browser origin is not allowed — use `XWA_CORS_ORIGINS` |
| `400` with `confirm=true` message | Graduated probing is opt-in by design; pass `confirm: true` (UI switch) |
| `502` on analyze | Target unreachable (DNS, TLS, connection). Check `error_message` in the response |
| `429` on repeated requests | Kabuki API rate limit (`KABUKI_RATE_LIMIT_MAX`, default 120/min) or the target's own rate limit (stored in `rate_limit_observations`) |
| Angular CLI version mismatch | Node below 24.15 — `kabuki.sh` prepends the mise Node 24 directory |
| `xwa-sdk` install fails | Sibling repo missing and no network access to GitHub — see `requirements.txt` for both options |
