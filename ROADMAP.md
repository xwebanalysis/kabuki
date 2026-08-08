# Kabuki Development Roadmap

This document tracks the strategic steps required to evolve the Kabuki application into a full-scale WAF and CDN analysis module.
This file is formatted to be synced automatically with GitHub Issues using the `xgh` roadmap standard.

## Infrastructure & Core Initialization <!-- phase:infrastructure -->

- [ ] Scaffold backend and frontend project structure
- [ ] Dockerize environments with local development HMR support
- [ ] Configure Docker-compose for rapid local development
- [ ] Define shared result data model aligned with xwa-sdk

## WAF Fingerprinting <!-- phase:waf-fingerprint -->

- [ ] Detect WAF presence from response signatures
- [ ] Fingerprint common WAF vendors (Cloudflare, Akamai, AWS WAF, Imperva, etc.)
- [ ] Implement rule-based and heuristic detection layers
- [ ] Build evasion-resistant probing techniques

## Challenge Mechanism Analysis <!-- phase:challenge-analysis -->

- [ ] Detect CAPTCHA and JS challenge responses
- [ ] Analyze challenge-based blocking patterns and headers
- [ ] Profile challenge bypass indicators and response times
- [ ] Classify challenge severity by request context

## Rate-Limit Profiling <!-- phase:rate-limit -->

- [ ] Profile rate-limit headers (RateLimit-*, Retry-After)
- [ ] Measure threshold detection via graduated probing
- [ ] Detect IP vs. session-based limiting strategies
- [ ] Generate safe rate-limit recommendations for scraping tools

## CDN Detection & Mapping <!-- phase:cdn-detection -->

- [ ] Detect CDN presence from DNS and TLS fingerprints
- [ ] Map edge node IP ranges to providers
- [ ] Identify origin-obfuscation techniques
- [ ] Analyze caching behavior and stale-response indicators

## Reporting & Production Hardening <!-- phase:production-hardening -->

- [ ] Build WAF/CDN composition report generator
- [ ] Create JSON export for analysis profiles
- [ ] Wrap backend routes with JWT Authentication middleware
- [ ] Implement rate limiting and access controls
