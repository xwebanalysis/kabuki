"""Kabuki analysis core — WAF/CDN fingerprinting, challenge and rate-limit profiling.

Safety model (anti-blocking, per the XWA standard):

- ``headers`` mode (default): exactly **one** GET probe. Headers, cookies, body
  markers and a single status code are enough for passive fingerprinting.
- ``graduated`` mode: opt-in only (``confirm=True``), bounded by
  ``max_requests`` (default 5, hard cap 20), 500–1500 ms jittered delay between
  requests and immediate abort on the first ``429``/``403``.
- No subprocesses, no evasion payloads, no credential/session manipulation.
  The default User-Agent identifies the tool.
- DNS (CNAME chain) uses ``dnspython`` and TLS inspection uses the standard
  library in a worker thread; both are best-effort and never fatal.
"""

from __future__ import annotations

import asyncio
import json
import random
import re
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Sequence
from urllib.parse import urlparse

import httpx

try:  # optional at import time; required for the DNS/CNAME phase
    import dns.exception
    import dns.resolver

    DNS_AVAILABLE = True
except Exception:  # pragma: no cover - dependency missing
    dns = None  # type: ignore[assignment]
    DNS_AVAILABLE = False


# ── Constants ────────────────────────────────────────────────────────────────

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (compatible; Kabuki/0.1; +https://github.com/xwebanalysis/kabuki) "
    "WAF-CDN-analyzer"
)
PROBE_MODES = ("headers", "graduated")
DEFAULT_MAX_REQUESTS = 5
MAX_MAX_REQUESTS = 20
MIN_DELAY_MS = 500
MAX_DELAY_MS = 1500
MAX_REDIRECTS = 5
REQUEST_TIMEOUT = 15.0
BODY_LIMIT = 200_000

SEVERITIES = ("pass", "info", "low", "medium", "high", "critical")

CHALLENGE_SEVERITY = {
    "captcha": "medium",
    "js_challenge": "medium",
    "block_page": "high",
    "interstitial": "low",
}

CHALLENGE_MARKERS: dict[str, tuple[str, ...]] = {
    # Only concrete CAPTCHA artifacts, never the bare word (marketing/docs pages
    # mention "captcha" without serving one).
    "captcha": (
        "g-recaptcha",
        "grecaptcha",
        "hcaptcha",
        "h-captcha",
        "cf-turnstile",
        "data-sitekey",
        "recaptcha/api.js",
        "challenges.cloudflare.com/turnstile",
    ),
    "js_challenge": (
        "cf-chl",
        "jschl",
        "challenge-platform",
        "__cf_chl",
        "cf_chl_opt",
        "challenge-form",
        "jschl-answer",
        "_cf_chl_tk",
    ),
    "block_page": (
        "access denied",
        "request blocked",
        "you have been blocked",
        "attention required",
        "incident id",
        "not acceptable!",
        "error 1020",
        "security check",
    ),
    "interstitial": (
        "checking your browser",
        "just a moment",
        "one more step",
        "verifying you are human",
        "enable javascript and cookies to continue",
        "ddos protection by",
        "please wait while we verify",
    ),
}

# Interstitial markers strong enough to fire on a 200 response by themselves.
STRONG_INTERSTITIAL_MARKERS = (
    "checking your browser",
    "just a moment",
    "one more step",
    "verifying you are human",
    "enable javascript and cookies to continue",
)


class TargetError(Exception):
    """The target could not be fetched (DNS, TLS, connection, timeout)."""


class InvalidTargetError(Exception):
    """The target is not a valid http(s) URL."""


class ProbeRefusedError(Exception):
    """The requested probe mode violates the anti-blocking guardrails."""


# ── Data structures ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class HeaderRule:
    """A header signature. ``header`` may end with ``*`` for a prefix match."""

    header: str
    pattern: str
    confidence: str = "medium"
    product: str | None = None


@dataclass(frozen=True)
class WafSignature:
    vendor: str
    product: str | None = None
    headers: tuple[HeaderRule, ...] = ()
    cookie_patterns: tuple[str, ...] = ()
    body_patterns: tuple[str, ...] = ()
    blocked_status: tuple[int, ...] = (403, 429, 503)
    severity: str = "info"


@dataclass(frozen=True)
class CdnSignature:
    provider: str
    headers: tuple[HeaderRule, ...] = ()
    edge_headers: tuple[str, ...] = ()
    caching_headers: tuple[str, ...] = ()


@dataclass
class ProbeResponse:
    method: str
    url: str
    final_url: str
    status_code: int
    headers: dict[str, str]
    cookies: list[str]
    body: str
    elapsed_ms: float


@dataclass
class WafData:
    vendor: str
    product: str | None
    confidence: str
    detection_method: str
    evidence: str
    blocked: bool = False
    severity: str = "info"


@dataclass
class CdnData:
    provider: str
    edge_nodes: list[str] = field(default_factory=list)
    origin_hidden: bool = False
    caching: str | None = None
    evidence: str | None = None


@dataclass
class ChallengeData:
    kind: str
    status_code: int | None
    headers: dict[str, str] = field(default_factory=dict)
    bypass_indicators: list[str] = field(default_factory=list)
    response_time_ms: float | None = None
    severity_hint: str = "info"


@dataclass
class RateLimitData:
    scope: str
    limit: int | None = None
    window_seconds: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    threshold_estimate: int | None = None
    recommended_delay_ms: int | None = None


@dataclass
class FindingData:
    severity: str
    category: str
    check: str
    title: str
    description: str
    target_url: str
    evidence: dict[str, Any] = field(default_factory=dict)
    confidence: str | None = None
    cvss_score: str | None = None
    tool: str = "kabuki"


# ── WAF signature database (27 vendors) ─────────────────────────────────────

WAF_SIGNATURES: tuple[WafSignature, ...] = (
    WafSignature(
        vendor="Cloudflare",
        product="Cloudflare WAF",
        headers=(
            HeaderRule("server", r"^cloudflare$", "high"),
            HeaderRule("cf-ray", r".+", "high"),
            HeaderRule("cf-mitigated", r".+", "high"),
            HeaderRule("cf-cache-status", r".+", "medium"),
            HeaderRule("cf-request-id", r".+", "medium"),
        ),
        cookie_patterns=(r"__cfduid", r"cf_clearance", r"__cf_bm"),
        body_patterns=(
            r"attention required!?\s*\|?\s*cloudflare",
            r"cloudflare ray id",
            r"cf-browser-verification",
            r"checking your browser before accessing",
            r"enable javascript and cookies to continue",
        ),
    ),
    WafSignature(
        vendor="Akamai",
        product="Akamai Web Application Protector",
        headers=(
            HeaderRule("server", r"akamaighost", "high"),
            HeaderRule("akamai-grn", r".+", "high"),
            HeaderRule("x-akamai-transformed", r".+", "medium"),
            HeaderRule("x-akamai-request-id", r".+", "medium"),
        ),
        cookie_patterns=(r"ak_bmsc", r"bm_sz", r"_abck"),
        body_patterns=(r"reference\s*#\d+", r"akamai reference"),
    ),
    WafSignature(
        vendor="AWS",
        product="AWS WAF",
        headers=(
            HeaderRule("x-amzn-waf-action", r".+", "high"),
            HeaderRule("x-amzn-requestid", r".+", "low"),
        ),
        body_patterns=(r"request blocked", r"<title>403 forbidden</title>"),
    ),
    WafSignature(
        vendor="Amazon",
        product="Amazon CloudFront",
        headers=(
            HeaderRule("x-amz-cf-id", r".+", "high"),
            HeaderRule("x-amz-cf-pop", r".+", "high"),
            HeaderRule("via", r"cloudfront", "medium"),
            HeaderRule("server", r"^cloudfront$", "medium"),
        ),
        blocked_status=(403, 429),
    ),
    WafSignature(
        vendor="Imperva",
        product="Imperva Incapsula",
        headers=(
            HeaderRule("x-iinfo", r".+", "high"),
            HeaderRule("x-cdn", r"incapsula", "high"),
        ),
        cookie_patterns=(r"incap_ses_", r"visid_incap_", r"nlbi_"),
        body_patterns=(r"_incapsula_resource", r"incapsula incident id", r"incapsula"),
    ),
    WafSignature(
        vendor="Sucuri",
        product="Sucuri CloudProxy",
        headers=(
            HeaderRule("server", r"sucuri", "high"),
            HeaderRule("x-sucuri-id", r".+", "high"),
            HeaderRule("x-sucuri-cache", r".+", "medium"),
        ),
        body_patterns=(r"sucuri website firewall", r"access denied - sucuri"),
    ),
    WafSignature(
        vendor="F5",
        product="F5 BIG-IP ASM",
        headers=(HeaderRule("x-wa-info", r".+", "medium"),),
        cookie_patterns=(r"^bigipserver", r"^ts[0-9a-f]{8}$"),
        body_patterns=(
            r"the requested url was rejected",
            r"please consult with your administrator",
        ),
    ),
    WafSignature(
        vendor="Fortinet",
        product="FortiWeb",
        headers=(HeaderRule("server", r"fortiweb", "high"),),
        body_patterns=(r"fortiweb", r"fortigate"),
    ),
    WafSignature(
        vendor="Barracuda",
        product="Barracuda WAF",
        headers=(HeaderRule("server", r"barracuda", "high"),),
        cookie_patterns=(r"barra_counter_session", r"bni_persistence"),
        body_patterns=(r"barracuda networks",),
    ),
    WafSignature(
        vendor="Fastly",
        product="Fastly / Signal Sciences",
        headers=(
            HeaderRule("x-sigsci-requestid", r".+", "high"),
            HeaderRule("x-sigsci-tags", r".+", "high"),
            HeaderRule("x-served-by", r"^cache-", "high"),
            HeaderRule("fastly-debug-digest", r".+", "high"),
            HeaderRule("x-fastly-request-id", r".+", "medium"),
        ),
        cookie_patterns=(r"sig-sci",),
    ),
    WafSignature(
        vendor="Vercel",
        product="Vercel Edge Network",
        headers=(
            HeaderRule("server", r"^vercel$", "high"),
            HeaderRule("x-vercel-id", r".+", "high"),
            HeaderRule("x-vercel-cache", r".+", "medium"),
        ),
        blocked_status=(403, 429),
    ),
    WafSignature(
        vendor="Netlify",
        product="Netlify Edge",
        headers=(
            HeaderRule("server", r"^netlify$", "high"),
            HeaderRule("x-nf-request-id", r".+", "high"),
        ),
        blocked_status=(429,),
    ),
    WafSignature(
        vendor="Google",
        product="Google Cloud Armor",
        headers=(
            HeaderRule("x-cloud-trace-context", r".+", "medium"),
            HeaderRule("server", r"(google frontend|gfe)", "medium"),
        ),
        body_patterns=(r"the request is blocked", r"google cloud armor"),
    ),
    WafSignature(
        vendor="Microsoft",
        product="Azure Front Door",
        headers=(
            HeaderRule("x-azure-ref", r".+", "high"),
            HeaderRule("x-fd-int-roxy-purgeid", r".+", "high"),
            HeaderRule("x-azure-fdid", r".+", "high"),
            HeaderRule("server", r"microsoft-azure-application-gateway", "medium"),
        ),
    ),
    WafSignature(
        vendor="ModSecurity",
        product="ModSecurity CRS",
        headers=(HeaderRule("server", r"modsecurity", "high"),),
        body_patterns=(
            r"mod_security",
            r"modsecurity",
            r"this error was generated by mod_security",
            r"not acceptable! an appropriate representation",
        ),
    ),
    WafSignature(
        vendor="Wordfence",
        product="Wordfence WAF",
        headers=(HeaderRule("x-wordfence", r".+", "medium"),),
        cookie_patterns=(r"wfwaf-authcookie",),
        body_patterns=(
            r"generated by wordfence",
            r"wordfence web application firewall",
            r"your access to this site has been limited",
        ),
    ),
    WafSignature(
        vendor="StackPath",
        product="StackPath Edge",
        headers=(
            HeaderRule("server", r"stackpath", "high"),
            HeaderRule("x-sp-cache", r".+", "high"),
        ),
        blocked_status=(403,),
    ),
    WafSignature(
        vendor="Bunny",
        product="Bunny CDN",
        headers=(
            HeaderRule("server", r"bunnycdn", "high"),
            HeaderRule("cdn-request-id", r".+", "medium"),
            HeaderRule("bunnycdn-cache", r".+", "medium"),
        ),
    ),
    WafSignature(
        vendor="KeyCDN",
        product="KeyCDN Edge",
        headers=(HeaderRule("server", r"keycdn", "high"),),
    ),
    WafSignature(
        vendor="Reblaze",
        product="Reblaze WAF",
        headers=(HeaderRule("server", r"reblaze", "high"),),
        cookie_patterns=(r"rbzid",),
    ),
    WafSignature(
        vendor="Wallarm",
        product="Wallarm WAF",
        headers=(HeaderRule("server", r"wallarm", "high"),),
        body_patterns=(r"wallarm",),
    ),
    WafSignature(
        vendor="DataDome",
        product="DataDome Bot Protection",
        headers=(
            HeaderRule("x-datadome", r".+", "high"),
            HeaderRule("x-dd-b", r".+", "high"),
            HeaderRule("server", r"datadome", "high"),
        ),
        cookie_patterns=(r"datadome",),
        body_patterns=(r"datadome", r"dd_cookie_test"),
    ),
    WafSignature(
        vendor="HUMAN",
        product="HUMAN Security (PerimeterX)",
        headers=(HeaderRule("x-px-", r".+", "high"),),
        cookie_patterns=(r"^_px",),
        body_patterns=(r"perimeterx", r"px-captcha", r"_pxhd"),
    ),
    WafSignature(
        vendor="Kasada",
        product="Kasada Bot Defense",
        headers=(
            HeaderRule("x-kpsdk-ct", r".+", "high"),
            HeaderRule("x-kpsdk-cd", r".+", "high"),
        ),
        body_patterns=(r"kpsdk",),
    ),
    WafSignature(
        vendor="Citrix",
        product="Citrix NetScaler",
        headers=(
            HeaderRule("server", r"netscaler", "high"),
            HeaderRule("via", r"ns-cache", "medium"),
        ),
        cookie_patterns=(r"citrix_ns_id", r"ns_af"),
    ),
    WafSignature(
        vendor="Radware",
        product="Radware WAF",
        headers=(HeaderRule("server", r"radware", "high"),),
        body_patterns=(r"radware",),
    ),
    WafSignature(
        vendor="Alibaba Cloud",
        product="Alibaba Cloud WAF",
        headers=(
            HeaderRule("server", r"yundun", "high"),
            HeaderRule("x-server-dio", r".+", "low"),
        ),
        body_patterns=(r"yundun", r"aliyun"),
    ),
)


# ── CDN signature database ───────────────────────────────────────────────────

CDN_SIGNATURES: tuple[CdnSignature, ...] = (
    CdnSignature(
        provider="Cloudflare",
        headers=(
            HeaderRule("server", r"^cloudflare$", "high"),
            HeaderRule("cf-ray", r".+", "high"),
            HeaderRule("cf-cache-status", r".+", "high"),
        ),
        edge_headers=("cf-ray", "x-served-by"),
        caching_headers=("cf-cache-status",),
    ),
    CdnSignature(
        provider="Akamai",
        headers=(
            HeaderRule("server", r"akamaighost", "high"),
            HeaderRule("akamai-grn", r".+", "high"),
            HeaderRule("x-akamai-transformed", r".+", "medium"),
        ),
        edge_headers=("akamai-grn", "x-akamai-request-id"),
        caching_headers=("x-cache", "x-akamai-cache-status"),
    ),
    CdnSignature(
        provider="Amazon CloudFront",
        headers=(
            HeaderRule("x-amz-cf-id", r".+", "high"),
            HeaderRule("x-amz-cf-pop", r".+", "high"),
            HeaderRule("via", r"cloudfront", "medium"),
        ),
        edge_headers=("x-amz-cf-pop", "x-amz-cf-id"),
        caching_headers=("x-cache", "age"),
    ),
    CdnSignature(
        provider="Fastly",
        headers=(
            HeaderRule("x-served-by", r"^cache-", "high"),
            HeaderRule("fastly-debug-digest", r".+", "high"),
            HeaderRule("x-fastly-request-id", r".+", "high"),
            HeaderRule("via", r"varnish", "medium"),
        ),
        edge_headers=("x-served-by", "x-fastly-request-id"),
        caching_headers=("x-cache", "x-served-by", "age"),
    ),
    CdnSignature(
        provider="Vercel",
        headers=(
            HeaderRule("server", r"^vercel$", "high"),
            HeaderRule("x-vercel-id", r".+", "high"),
            HeaderRule("x-vercel-cache", r".+", "high"),
        ),
        edge_headers=("x-vercel-id",),
        caching_headers=("x-vercel-cache", "age"),
    ),
    CdnSignature(
        provider="Netlify",
        headers=(
            HeaderRule("server", r"^netlify$", "high"),
            HeaderRule("x-nf-request-id", r".+", "high"),
        ),
        edge_headers=("x-nf-request-id",),
        caching_headers=("age", "x-nf-request-id"),
    ),
    CdnSignature(
        provider="Google Cloud CDN",
        headers=(
            HeaderRule("server", r"(google frontend|gfe)", "medium"),
            HeaderRule("x-cloud-trace-context", r".+", "medium"),
        ),
        edge_headers=("x-cloud-trace-context",),
        caching_headers=("age", "x-cache"),
    ),
    CdnSignature(
        provider="Azure Front Door",
        headers=(
            HeaderRule("x-azure-ref", r".+", "high"),
            HeaderRule("x-fd-int-roxy-purgeid", r".+", "high"),
        ),
        edge_headers=("x-azure-ref", "x-fd-int-roxy-purgeid"),
        caching_headers=("x-cache", "age"),
    ),
    CdnSignature(
        provider="Bunny CDN",
        headers=(
            HeaderRule("server", r"bunnycdn", "high"),
            HeaderRule("cdn-request-id", r".+", "medium"),
        ),
        edge_headers=("cdn-request-id",),
        caching_headers=("cdn-cache", "x-cache", "age"),
    ),
    CdnSignature(
        provider="KeyCDN",
        headers=(HeaderRule("server", r"keycdn", "high"),),
        edge_headers=("server",),
        caching_headers=("x-cache", "age"),
    ),
    CdnSignature(
        provider="StackPath",
        headers=(
            HeaderRule("server", r"stackpath", "high"),
            HeaderRule("x-sp-cache", r".+", "high"),
        ),
        edge_headers=("x-sp-cache",),
        caching_headers=("x-sp-cache", "age"),
    ),
    CdnSignature(
        provider="Imperva",
        headers=(
            HeaderRule("x-cdn", r"incapsula", "high"),
            HeaderRule("x-iinfo", r".+", "medium"),
        ),
        edge_headers=("x-iinfo",),
        caching_headers=("x-cache", "age"),
    ),
    CdnSignature(
        provider="Sucuri",
        headers=(
            HeaderRule("server", r"sucuri", "high"),
            HeaderRule("x-sucuri-cache", r".+", "high"),
        ),
        edge_headers=("x-sucuri-id", "x-sucuri-cache"),
        caching_headers=("x-sucuri-cache", "age"),
    ),
    CdnSignature(
        provider="Alibaba Cloud CDN",
        headers=(
            HeaderRule("server", r"(tengine|alibabacloud)", "medium"),
            HeaderRule("ali-swift-global-savetime", r".+", "high"),
            HeaderRule("eagleid", r".+", "high"),
        ),
        edge_headers=("eagleid", "ali-swift-global-savetime"),
        caching_headers=("x-cache", "age"),
    ),
)

TLS_ISSUER_HINTS: tuple[tuple[str, str], ...] = (
    ("cloudflare", "Cloudflare"),
    ("google trust services", "Google Cloud CDN"),
    ("google internet authority", "Google Cloud CDN"),
    ("amazon", "Amazon CloudFront"),
    ("fastly", "Fastly"),
    ("stackpath", "StackPath"),
)

CACHE_STATUS_MAP = {
    "hit": "hit",
    "miss": "miss",
    "stale": "stale",
    "expired": "stale",
    "dynamic": "miss",
    "bypass": "miss",
    "revalidated": "stale",
    "updating": "stale",
    "cookie": "miss",
}

CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}

ProgressCallback = Callable[[str, str, dict[str, Any] | None], Awaitable[None]]


# ── Public helpers ───────────────────────────────────────────────────────────


def normalize_target(target: str) -> str:
    """Return an absolute http(s) URL, adding ``https://`` when missing."""
    value = (target or "").strip()
    if not value:
        raise InvalidTargetError("Target is empty.")
    if "://" not in value:
        value = f"https://{value}"
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise InvalidTargetError(f"Unsupported target '{target}' (use an http(s) URL).")
    return value


def _headers_dict(response: httpx.Response) -> dict[str, str]:
    collected: dict[str, list[str]] = {}
    for name, value in response.headers.multi_items():
        collected.setdefault(name.lower(), []).append(value)
    return {name: ", ".join(values) for name, values in collected.items()}


def _to_probe(response: httpx.Response, method: str, elapsed_ms: float) -> ProbeResponse:
    return ProbeResponse(
        method=method,
        url=str(response.request.url) if response.request else str(response.url),
        final_url=str(response.url),
        status_code=response.status_code,
        headers=_headers_dict(response),
        cookies=response.headers.get_list("set-cookie"),
        body=response.text[:BODY_LIMIT],
        elapsed_ms=elapsed_ms,
    )


def _matching_headers(probe: ProbeResponse, rule: HeaderRule) -> list[tuple[str, str]]:
    """Return ``(name, value)`` pairs where the header rule matches."""
    pattern = rule.pattern
    if rule.header.endswith("*"):
        prefix = rule.header[:-1].lower()
        candidates = [(n, v) for n, v in probe.headers.items() if n.startswith(prefix)]
    else:
        name = rule.header.lower()
        if name not in probe.headers:
            return []
        candidates = [(name, probe.headers[name])]
    matches = []
    for name, value in candidates:
        try:
            if re.search(pattern, value, re.IGNORECASE):
                matches.append((name, value))
        except re.error:
            continue
    return matches


def _best_evidence(candidates: list[tuple[str, str, str]]) -> str:
    """Join the strongest evidence candidates, most readable first."""
    ordered = sorted(candidates, key=lambda c: CONFIDENCE_RANK.get(c[2], 0), reverse=True)
    rendered = [f"{name}: {value}" for name, value, _ in ordered[:3]]
    return " | ".join(rendered)[:500]


def fingerprint_waf(probe: ProbeResponse) -> list[WafData]:
    """Match a probe against the WAF signature database."""
    results: list[WafData] = []
    body = probe.body or ""
    cookie_blob = " ".join(probe.cookies)

    for signature in WAF_SIGNATURES:
        candidates: list[tuple[str, str, str]] = []  # (name, value, confidence)

        for rule in signature.headers:
            for name, value in _matching_headers(probe, rule):
                candidates.append((name, value, rule.confidence))

        for pattern in signature.cookie_patterns:
            for cookie in probe.cookies:
                if re.search(pattern, cookie, re.IGNORECASE):
                    cookie_name = cookie.split("=", 1)[0].strip()
                    candidates.append(("set-cookie", cookie_name, "high"))
                    break

        for pattern in signature.body_patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                snippet = body[max(0, match.start() - 20) : match.end() + 40]
                candidates.append(("body", snippet.strip(), "medium"))

        if not candidates:
            continue

        candidates.sort(key=lambda c: CONFIDENCE_RANK.get(c[2], 0), reverse=True)
        best_name, best_value, best_confidence = candidates[0]
        method = "header"
        if best_name == "set-cookie":
            method = "cookie"
        elif best_name == "body":
            method = "body"

        blocked = probe.status_code in signature.blocked_status and method in ("body", "header", "cookie")
        results.append(
            WafData(
                vendor=signature.vendor,
                product=signature.product,
                confidence=best_confidence,
                detection_method=method,
                evidence=_best_evidence(candidates),
                blocked=bool(blocked),
                severity=signature.severity,
            )
        )

    results.sort(key=lambda w: CONFIDENCE_RANK.get(w.confidence, 0), reverse=True)
    return results


def detect_challenges(probes: Sequence[ProbeResponse]) -> list[ChallengeData]:
    """Detect CAPTCHA / JS challenge / block / interstitial pages."""
    found: dict[str, ChallengeData] = {}

    for probe in probes:
        body = (probe.body or "").lower()
        scores: dict[str, int] = {}
        for kind, markers in CHALLENGE_MARKERS.items():
            score = sum(1 for marker in markers if marker in body)
            if score:
                scores[kind] = score
        strong_body = any(marker in body for marker in STRONG_INTERSTITIAL_MARKERS)
        interesting_status = probe.status_code in (403, 429, 503)

        if not interesting_status:
            # On an informational response keep only artifacts specific enough:
            # CAPTCHA/JS markers, a strong interstitial, or two block markers.
            filtered: dict[str, int] = {}
            for kind, score in scores.items():
                if kind in ("captcha", "js_challenge"):
                    filtered[kind] = score
                elif kind == "interstitial" and strong_body:
                    filtered[kind] = score
                elif kind == "block_page" and score >= 2:
                    filtered[kind] = score
            scores = filtered

        if not scores:
            continue

        priority = {"js_challenge": 0, "captcha": 1, "interstitial": 2, "block_page": 3}
        kind = sorted(scores.items(), key=lambda item: (-item[1], priority[item[0]]))[0][0]

        indicator_pool = {
            "js_challenge": "challenge-platform",
            "captcha": "captcha-sitekey",
            "interstitial": "interstitial-page",
            "block_page": "hard-block-page",
        }
        indicators = [indicator_pool[kind]]
        if kind == "js_challenge" and "<noscript" in body:
            indicators.append("no_js_fallback")
        if kind == "captcha" and ("sitekey" in body or "data-sitekey" in body):
            indicators.append("captcha_sitekey_present")
        if any("cf_clearance" in cookie for cookie in probe.cookies):
            indicators.append("challenge_cookie_present")
        if "retry-after" in probe.headers:
            indicators.append("retry_after_guidance")
        if kind == "js_challenge" and probe.status_code == 200:
            indicators.append("soft_challenge_200")
        if kind == "block_page" and probe.status_code == 403:
            indicators.append("status_403")

        relevant = {
            name: value
            for name, value in probe.headers.items()
            if name
            in (
                "server",
                "cf-ray",
                "cf-mitigated",
                "x-amzn-waf-action",
                "x-iinfo",
                "x-datadome",
                "x-kpsdk-ct",
                "retry-after",
                "www-authenticate",
                "content-type",
                "location",
            )
        }

        if kind not in found:
            found[kind] = ChallengeData(
                kind=kind,
                status_code=probe.status_code,
                headers=relevant,
                bypass_indicators=sorted(set(indicators)),
                response_time_ms=round(probe.elapsed_ms, 1),
                severity_hint=CHALLENGE_SEVERITY.get(kind, "info"),
            )

    return list(found.values())


def _first_int(value: str | None) -> int | None:
    if not value:
        return None
    match = re.search(r"\d+", value)
    return int(match.group()) if match else None


def _parse_retry_after(value: str | None) -> int | None:
    """Return Retry-After in seconds (delta or HTTP-date)."""
    if not value:
        return None
    value = value.strip()
    seconds = _first_int(value)
    if seconds is not None and value.isdigit():
        return seconds
    try:
        from email.utils import parsedate_to_datetime

        when = parsedate_to_datetime(value)
        delta = when.timestamp() - datetime.now(timezone.utc).timestamp()
        return max(0, int(delta))
    except Exception:
        return seconds


def parse_rate_limit(
    probe: ProbeResponse,
    probes: Sequence[ProbeResponse] | None = None,
    aborted: bool = False,
) -> RateLimitData:
    """Parse RateLimit-*/X-RateLimit-*/Retry-After headers into a profile.

    Headers are merged from every probe (primary first, later probes override),
    so a ``Retry-After`` returned by the aborting 429 is still captured.
    """
    raw: dict[str, str] = {}
    for source in probes or [probe]:
        for name, value in source.headers.items():
            lower = name.lower()
            if (
                lower.startswith("ratelimit-")
                or lower.startswith("x-ratelimit-")
                or lower == "retry-after"
            ):
                raw[lower] = value

    limit = _first_int(
        raw.get("ratelimit-limit")
        or raw.get("x-ratelimit-limit")
        or raw.get("x-rate-limit-limit")
    )
    window = None
    policy = raw.get("ratelimit-policy") or raw.get("x-ratelimit-policy")
    if policy:
        match = re.search(r"w\s*=\s*(\d+)", policy, re.IGNORECASE)
        if match:
            window = int(match.group(1))
    if window is None:
        window = _first_int(raw.get("x-ratelimit-window") or raw.get("x-rate-limit-window"))

    retry_after = _parse_retry_after(raw.get("retry-after"))

    scope = "unknown"
    explicit_scope = (raw.get("x-ratelimit-scope") or raw.get("ratelimit-scope") or "").lower()
    if explicit_scope in ("ip", "session", "global", "unknown"):
        scope = explicit_scope
    elif any(key.startswith(("ratelimit-", "x-ratelimit-")) and key not in ("ratelimit-policy",) for key in raw):
        scope = "ip"
    elif aborted:
        scope = "ip"

    threshold = None
    if probes:
        successful = sum(1 for item in probes[:-1] if item.status_code < 400)
        if aborted and probes[-1].status_code in (403, 429):
            threshold = successful

    recommended = None
    if retry_after is not None:
        recommended = max(500, min(retry_after * 1000, 60_000))
    elif limit and window:
        recommended = max(500, min(int((window * 1000 / limit) * 2), 60_000))
    else:
        recommended = 2000  # conservative default when nothing is advertised

    header_snapshot = dict(sorted(raw.items()))
    return RateLimitData(
        scope=scope,
        limit=limit,
        window_seconds=window,
        headers=header_snapshot,
        threshold_estimate=threshold,
        recommended_delay_ms=recommended,
    )


def _cache_status(probe: ProbeResponse) -> str:
    for header, value in probe.headers.items():
        lower = header.lower()
        if lower in ("cf-cache-status", "x-cache", "x-vercel-cache", "x-sp-cache", "cdn-cache"):
            token = value.split(",")[0].strip().split(" ")[0].lower()
            if token in CACHE_STATUS_MAP:
                return CACHE_STATUS_MAP[token]
    age = _first_int(probe.headers.get("age"))
    if age is not None and age > 0:
        return "hit"
    return "unknown"


def _tls_provider_hint(tls_info: dict[str, Any] | None) -> str | None:
    if not tls_info:
        return None
    issuer = " ".join(
        str(tls_info.get(key) or "")
        for key in ("issuer_organization", "issuer_common_name")
    ).lower()
    for fragment, provider in TLS_ISSUER_HINTS:
        if fragment in issuer:
            return provider
    return None


def detect_cdn(
    probe: ProbeResponse,
    dns_info: dict[str, list[str]] | None = None,
    tls_info: dict[str, Any] | None = None,
) -> CdnData | None:
    """Identify the CDN provider and collect observed edge nodes."""
    dns_info = dns_info or {"cnames": [], "addresses": []}
    best: tuple[int, str, str] | None = None  # (rank, provider, evidence)

    for signature in CDN_SIGNATURES:
        for rule in signature.headers:
            matches = _matching_headers(probe, rule)
            if not matches:
                continue
            name, value = matches[0]
            rank = CONFIDENCE_RANK.get(rule.confidence, 0)
            if best is None or rank > best[0]:
                best = (rank, signature.provider, f"{name}: {value[:120]}")

    provider = None
    evidence = None
    if best is not None:
        provider, evidence = best[1], best[2]
    else:
        hint = _tls_provider_hint(tls_info)
        if hint:
            provider = hint
            evidence = f"tls issuer: {tls_info.get('issuer_organization') or tls_info.get('issuer_common_name')}"

    if provider is None:
        return None

    edge_nodes: list[str] = []

    def add_node(value: str | None) -> None:
        if value and value not in edge_nodes:
            edge_nodes.append(value[:200])

    for signature in CDN_SIGNATURES:
        if signature.provider != provider:
            continue
        for header in signature.edge_headers:
            value = probe.headers.get(header)
            if not value:
                continue
            if header == "cf-ray":
                pop = value.rsplit("-", 1)[-1]
                add_node(f"pop:{pop}")
            else:
                add_node(value)

    for cname in dns_info.get("cnames", []):
        add_node(cname)
    for address in dns_info.get("addresses", []):
        add_node(address)

    return CdnData(
        provider=provider,
        edge_nodes=edge_nodes[:20],
        origin_hidden=bool(dns_info.get("cnames")),
        caching=_cache_status(probe),
        evidence=evidence,
    )


def resolve_dns_chain(host: str, resolver: Any | None = None) -> dict[str, list[str]]:
    """Best-effort CNAME chain + address resolution via dnspython.

    ``resolver`` can be injected in tests. Returns ``{"cnames": [...],
    "addresses": [...]}``; never raises.
    """
    result: dict[str, list[str]] = {"cnames": [], "addresses": []}
    if not DNS_AVAILABLE or not host:
        return result

    try:
        active = resolver or dns.resolver.Resolver()
        try:
            active.lifetime = 5.0
        except Exception:
            pass

        current = host
        seen: set[str] = set()
        for _ in range(8):
            try:
                answers = active.resolve(current, "CNAME")
            except Exception:
                break
            target = str(answers[0].target).rstrip(".").lower()
            if not target or target in seen:
                break
            seen.add(target)
            result["cnames"].append(target)
            current = target

        for rrtype in ("A", "AAAA"):
            try:
                for answer in active.resolve(host, rrtype):
                    value = str(answer)
                    if value not in result["addresses"]:
                        result["addresses"].append(value)
            except Exception:
                continue
    except Exception:
        return result
    return result


def inspect_tls_issuer(host: str, port: int = 443, timeout: float = 6.0) -> dict[str, Any] | None:
    """Read the TLS certificate issuer of ``host:443`` using the stdlib.

    Runs blocking socket code; call through ``asyncio.to_thread``. Returns
    ``None`` when the connection or handshake fails.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except Exception:
        return None

    issuer = {key: value for rdn in cert.get("issuer", ()) for key, value in rdn}
    subject = {key: value for rdn in cert.get("subject", ()) for key, value in rdn}
    return {
        "issuer_organization": issuer.get("organizationName"),
        "issuer_common_name": issuer.get("commonName"),
        "subject_common_name": subject.get("commonName"),
        "not_after": cert.get("notAfter"),
    }


def _validate_request(probe_mode: str, confirm: bool, max_requests: int) -> None:
    if probe_mode not in PROBE_MODES:
        raise ProbeRefusedError(f"Unsupported probe_mode '{probe_mode}'.")
    if probe_mode == "graduated" and not confirm:
        raise ProbeRefusedError(
            "probe_mode='graduated' requires confirm=true (anti-blocking guardrail)."
        )
    if not 1 <= max_requests <= MAX_MAX_REQUESTS:
        raise ProbeRefusedError(
            f"max_requests must be between 1 and {MAX_MAX_REQUESTS} (got {max_requests})."
        )


async def _probe(
    client: httpx.AsyncClient,
    url: str,
    probe_mode: str,
    max_requests: int,
    delay_ms: tuple[int, int],
) -> tuple[list[ProbeResponse], bool, str | None]:
    """Run one (headers) or up to ``max_requests`` (graduated) requests."""
    responses: list[ProbeResponse] = []
    aborted = False
    abort_reason: str | None = None

    if probe_mode == "headers":
        method = "GET"
        started = asyncio.get_event_loop().time()
        response = await client.request(method, url)
        elapsed = (asyncio.get_event_loop().time() - started) * 1000
        responses.append(_to_probe(response, method, elapsed))
        return responses, False, None

    for index in range(max_requests):
        method = "GET" if index == 0 else "HEAD"
        started = asyncio.get_event_loop().time()
        response = await client.request(method, url)
        elapsed = (asyncio.get_event_loop().time() - started) * 1000
        responses.append(_to_probe(response, method, elapsed))

        if response.status_code in (403, 429):
            aborted = True
            abort_reason = f"HTTP {response.status_code} on probe {index + 1}"
            break

        if index < max_requests - 1:
            jitter = random.uniform(delay_ms[0], delay_ms[1]) / 1000
            if jitter > 0:
                await asyncio.sleep(jitter)

    return responses, aborted, abort_reason


def _build_findings(
    target_url: str,
    waf: Sequence[WafData],
    cdn: CdnData | None,
    challenges: Sequence[ChallengeData],
    rate_limit: RateLimitData,
) -> list[FindingData]:
    findings: list[FindingData] = []

    if waf:
        for detection in waf:
            product = f" / {detection.product}" if detection.product else ""
            findings.append(
                FindingData(
                    severity=detection.severity,
                    category="waf",
                    check="waf.fingerprint",
                    title=f"WAF detected: {detection.vendor}{product}",
                    description=(
                        f"A {detection.vendor} WAF fingerprint was identified via "
                        f"{detection.detection_method} signatures. "
                        + ("The probe was blocked by the WAF." if detection.blocked else "")
                    ).strip(),
                    target_url=target_url,
                    evidence={
                        "vendor": detection.vendor,
                        "product": detection.product,
                        "confidence": detection.confidence,
                        "detection_method": detection.detection_method,
                        "evidence": detection.evidence,
                        "blocked": detection.blocked,
                    },
                    confidence=detection.confidence,
                )
            )
    else:
        findings.append(
            FindingData(
                severity="info",
                category="waf",
                check="waf.absent",
                title="No WAF fingerprint detected",
                description=(
                    "No known WAF signature matched the single passive probe. "
                    "Absence of evidence is not evidence of absence."
                ),
                target_url=target_url,
                evidence={"probes": 1},
                confidence="medium",
            )
        )

    if cdn:
        findings.append(
            FindingData(
                severity="info",
                category="cdn",
                check="cdn.detected",
                title=f"CDN detected: {cdn.provider}",
                description=(
                    f"Edge/CDN fingerprints for {cdn.provider} were observed. "
                    f"Caching status: {cdn.caching or 'unknown'}."
                ),
                target_url=target_url,
                evidence={
                    "provider": cdn.provider,
                    "edge_nodes": cdn.edge_nodes,
                    "origin_hidden": cdn.origin_hidden,
                    "caching": cdn.caching,
                    "evidence": cdn.evidence,
                },
                confidence="high" if cdn.evidence else "medium",
            )
        )
        if not cdn.origin_hidden:
            findings.append(
                FindingData(
                    severity="low",
                    category="cdn",
                    check="cdn.origin_exposure",
                    title="Origin shielding not confirmed",
                    description=(
                        "The CDN was detected from response headers but no CNAME chain to "
                        "the provider was observed. The origin may be directly reachable; "
                        "no further probing was performed (anti-blocking policy)."
                    ),
                    target_url=target_url,
                    evidence={"provider": cdn.provider, "cname_chain": []},
                    confidence="low",
                )
            )
    else:
        findings.append(
            FindingData(
                severity="info",
                category="cdn",
                check="cdn.absent",
                title="No CDN fingerprint detected",
                description=(
                    "No CDN provider matched the response headers, DNS chain or TLS issuer."
                ),
                target_url=target_url,
                confidence="medium",
            )
        )

    for challenge in challenges:
        findings.append(
            FindingData(
                severity=challenge.severity_hint,
                category="challenge",
                check=f"challenge.{challenge.kind}",
                title=f"Challenge observed: {challenge.kind}",
                description=(
                    f"The target answered with a {challenge.kind} pattern "
                    f"(HTTP {challenge.status_code}). "
                    "Indicators were collected but no bypass was attempted."
                ),
                target_url=target_url,
                evidence={
                    "kind": challenge.kind,
                    "status_code": challenge.status_code,
                    "bypass_indicators": challenge.bypass_indicators,
                    "response_time_ms": challenge.response_time_ms,
                },
                confidence="high",
            )
        )

    if rate_limit.limit is not None:
        findings.append(
            FindingData(
                severity="info",
                category="rate_limit",
                check="rate_limit.headers_present",
                title=f"Rate limiting advertised: {rate_limit.limit} requests",
                description=(
                    f"Rate limit headers advertise {rate_limit.limit} requests per "
                    f"{rate_limit.window_seconds or '?'} s (scope: {rate_limit.scope})."
                ),
                target_url=target_url,
                evidence={
                    "limit": rate_limit.limit,
                    "window_seconds": rate_limit.window_seconds,
                    "scope": rate_limit.scope,
                    "headers": rate_limit.headers,
                },
                confidence="high",
            )
        )
    else:
        findings.append(
            FindingData(
                severity="info",
                category="rate_limit",
                check="rate_limit.headers_absent",
                title="No rate-limit headers advertised",
                description=(
                    "The response did not advertise RateLimit-*/X-RateLimit-* headers. "
                    f"Conservative recommendation: wait ~{rate_limit.recommended_delay_ms} ms "
                    "between requests."
                ),
                target_url=target_url,
                evidence={
                    "scope": rate_limit.scope,
                    "recommended_delay_ms": rate_limit.recommended_delay_ms,
                },
                confidence="medium",
            )
        )

    return findings


async def analyze_target(
    target: str,
    probe_mode: str = "headers",
    confirm: bool = False,
    max_requests: int = DEFAULT_MAX_REQUESTS,
    transport: httpx.AsyncBaseTransport | None = None,
    resolve_dns: bool = True,
    inspect_tls: bool = True,
    delay_ms: tuple[int, int] | None = None,
    on_progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Profile WAF, CDN, challenge and rate-limit behaviour of ``target``.

    Returns a plain dict consumed by ``main.py`` for persistence and streaming.
    Raises :class:`InvalidTargetError` (400), :class:`ProbeRefusedError` (400)
    or :class:`TargetError` (502).
    """
    delay_range = delay_ms or (MIN_DELAY_MS, MAX_DELAY_MS)
    _validate_request(probe_mode, confirm, max_requests)
    url = normalize_target(target)
    host = urlparse(url).hostname or ""

    async def progress(phase: str, message: str, data: dict[str, Any] | None = None) -> None:
        if on_progress is not None:
            await on_progress(phase, message, data)

    await progress("fingerprint", f"Probing {host} ({probe_mode} mode)")

    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            max_redirects=MAX_REDIRECTS,
            timeout=httpx.Timeout(REQUEST_TIMEOUT),
            transport=transport,
            headers={
                "User-Agent": DEFAULT_USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            },
        ) as client:
            probes, aborted, abort_reason = await _probe(
                client, url, probe_mode, max_requests, delay_range
            )
    except httpx.HTTPError as exc:
        raise TargetError(f"Failed to fetch target: {exc}") from exc

    primary = probes[0]
    waf = fingerprint_waf(primary)
    await progress(
        "fingerprint",
        f"HTTP {primary.status_code} in {primary.elapsed_ms:.0f} ms — "
        f"{len(waf)} WAF fingerprint(s)",
        {"status_code": primary.status_code, "waf_count": len(waf)},
    )

    await progress("challenge", "Analyzing challenge markers")
    challenges = detect_challenges(probes)
    await progress(
        "challenge",
        f"{len(challenges)} challenge pattern(s) observed",
        {"challenge_count": len(challenges)},
    )

    await progress("rate_limit", "Parsing rate-limit headers")
    rate_limit = parse_rate_limit(primary, probes=probes, aborted=aborted)
    await progress(
        "rate_limit",
        f"scope={rate_limit.scope} limit={rate_limit.limit or 'n/a'} "
        f"recommended_delay={rate_limit.recommended_delay_ms} ms",
        {
            "scope": rate_limit.scope,
            "limit": rate_limit.limit,
            "recommended_delay_ms": rate_limit.recommended_delay_ms,
        },
    )

    await progress("cdn", "Resolving DNS chain and TLS issuer")
    dns_info = (
        await asyncio.to_thread(resolve_dns_chain, host)
        if resolve_dns
        else {"cnames": [], "addresses": []}
    )
    tls_info = (
        await asyncio.to_thread(inspect_tls_issuer, host) if inspect_tls and host else None
    )
    cdn = detect_cdn(primary, dns_info, tls_info)
    await progress(
        "cdn",
        f"provider={cdn.provider if cdn else 'none'} "
        f"edge_nodes={len(cdn.edge_nodes) if cdn else 0}",
        {"provider": cdn.provider if cdn else None},
    )

    findings = _build_findings(primary.final_url, waf, cdn, challenges, rate_limit)
    blocked = bool(challenges) or any(item.blocked for item in waf)

    return {
        "final_url": primary.final_url,
        "status_code": primary.status_code,
        "blocked": blocked,
        "waf": waf,
        "cdn": cdn,
        "challenges": challenges,
        "rate_limit": rate_limit,
        "findings": findings,
        "dns": dns_info,
        "tls": tls_info,
        "guardrail": {
            "probe_mode": probe_mode,
            "max_requests": max_requests,
            "requests_sent": len(probes),
            "aborted": aborted,
            "abort_reason": abort_reason,
            "delay_ms_min": delay_range[0],
            "delay_ms_max": delay_range[1],
        },
    }


def result_to_json(result: dict[str, Any]) -> str:
    """Serialize an analysis result (used by tests and debugging)."""
    return json.dumps(result, default=str, ensure_ascii=False)
