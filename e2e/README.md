# Kabuki browser smoke test

Playwright/Chromium end-to-end check for the Kabuki UI: backend health, REST
analysis via the UI, history rendering, language toggle and analysis detail.

## Requirements

- Kabuki running locally: `./kabuki.sh local` (backend :8040, UI :4240)
- Playwright + Chromium. The shared interpreter used by the suite is
  `samurai/backend/.venv/bin/python`.

## Run

```bash
samurai/backend/.venv/bin/python kabuki/e2e/browser_smoke.py
# options: --frontend http://localhost:4240 --fixture-port 8108 --headed
```

The script starts its own local fixture server on `127.0.0.1:8108`, runs a real
analysis against it, asserts rendering happens without extra clicks, and fails
on any console or page error.

## Note

Angular 22 apps are zoneless: async state updated from HTTP/WebSocket callbacks
must call `ChangeDetectorRef.markForCheck()` (or use signals), otherwise the
view will not re-render. See `docs/ui-architecture.md`.
