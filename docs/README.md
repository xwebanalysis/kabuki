# Kabuki Documentation

Documentation for the Kabuki WAF and CDN analysis module.

| Document | Description |
|----------|-------------|
| [architecture.md](architecture.md) | Stack, layout, analysis pipeline, data model and safety model |
| [api.md](api.md) | REST and WebSocket API reference |
| [development.md](development.md) | Running, environment variables and verification |

## Quick orientation

- Kabuki is a self-contained web application: an Angular 22 frontend (:4240) and a FastAPI backend (:8040).
- Local mode is the default and uses SQLite; PostgreSQL is only used by the docker mode.
- The analysis pipeline is passive: one request by default, opt-in graduated probing with hard limits.
- Findings use the unified xwa-sdk severity scale (`pass|info|low|medium|high|critical`).
- Live stream events use the xwa-sdk `Event` envelope with the persisted `analysis_id`; REST errors use the xwa-sdk `Error` envelope.
- The UI follows the Nothing Design System shared across XWA modules (dark instrument panel + light mode, self-hosted Doto/Space Grotesk/Space Mono).

## Quick start

```bash
./kabuki.sh local all      # native run (SQLite): backend :8040 + frontend :4240
./kabuki.sh docker all     # full stack with PostgreSQL 17
```

See [development.md](development.md) for all execution modes and
[api.md](api.md) for the endpoint reference.
