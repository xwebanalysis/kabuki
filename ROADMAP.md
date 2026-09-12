# Kabuki Development Roadmap

This document tracks the strategic steps required to evolve the Kabuki application into a full-scale WAF and CDN analysis module.
This file is formatted to be synced automatically with GitHub Issues using the `xgh` roadmap standard.

## Infrastructure & Core Initialization <!-- phase:infrastructure -->

- [x] Scaffold backend and frontend project structure
- [x] Dockerize environments with local development HMR support
- [x] Configure Docker-compose for rapid local development
- [x] Define shared result data model aligned with xwa-sdk (`Waf`, `Cdn`, `Challenge`, `RateLimit`, `Finding`)
- [x] Local-first mode: SQLite + uv venv + xwa-sdk editable install (`./kabuki.sh local`)

## WAF Fingerprinting <!-- phase:waf-fingerprint -->

- [x] Detect WAF presence from response signatures
- [x] Fingerprint common WAF vendors (Cloudflare, Akamai, AWS WAF, Imperva, etc. — 27 signatures)
- [x] Implement rule-based and heuristic detection layers (headers/cookies/body/status with confidence scoring)
- [ ] Build evasion-resistant probing techniques — intentionally not implemented: it would violate the anti-blocking policy (see docs/architecture.md)

## Challenge Mechanism Analysis <!-- phase:challenge-analysis -->

- [x] Detect CAPTCHA and JS challenge responses
- [x] Analyze challenge-based blocking patterns and headers
- [ ] Profile challenge bypass indicators and response times — response time and conservative indicators are stored, but no bypass is attempted; advanced profiling stays pending
- [x] Classify challenge severity by request context (`severity_hint`: captcha/js medium, block page high, interstitial low)

## Rate-Limit Profiling <!-- phase:rate-limit -->

- [x] Profile rate-limit headers (RateLimit-*, Retry-After)
- [x] Measure threshold detection via graduated probing (opt-in `confirm=true`, abort on 429/403)
- [ ] Detect IP vs. session-based limiting strategies — current scope inference is best-effort (`ip`/`unknown`), cookie/session tracking is not implemented
- [x] Generate safe rate-limit recommendations for scraping tools (`recommended_delay_ms`)

## CDN Detection & Mapping <!-- phase:cdn-detection -->

- [x] Detect CDN presence from DNS and TLS fingerprints
- [ ] Map edge node IP ranges to providers — observed edge nodes are collected, full provider IP-range maps are pending
- [x] Identify origin-obfuscation techniques (CNAME-chain + header heuristic, `origin_hidden` flag)
- [x] Analyze caching behavior and stale-response indicators

## Reporting & Production Hardening <!-- phase:production-hardening -->

- [x] Build WAF/CDN composition report generator (client-side jsPDF report; server-side JSON/CSV)
- [x] Create JSON export for analysis profiles
- [x] Wrap backend routes with JWT Authentication middleware (optional via `KABUKI_JWT_SECRET`)
- [x] Implement rate limiting and access controls (`KABUKI_RATE_LIMIT_MAX`, `/api/health` exempt)
- [x] xwa-sdk `Event` streaming with persisted `analysis_id`, monotonic `seq` and UTC `ts`
