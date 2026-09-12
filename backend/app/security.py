"""Security helpers: configurable CORS, optional JWT auth and in-memory rate limiting."""

from __future__ import annotations

import os
import time
from collections import defaultdict, deque

import jwt as pyjwt
from fastapi import Request
from fastapi.responses import JSONResponse

JWT_SECRET = os.getenv("KABUKI_JWT_SECRET") or None
AUTH_PASSWORD = os.getenv("KABUKI_AUTH_PASSWORD", "kabuki")
TOKEN_TTL_HOURS = 24

RATE_LIMIT_MAX = int(
    os.getenv("KABUKI_RATE_LIMIT_MAX") or os.getenv("XWA_RATE_LIMIT_MAX") or "120"
)
RATE_LIMIT_WINDOW = 60.0

_hits: dict[str, deque[float]] = defaultdict(deque)

EXEMPT_PATHS = {
    "/",
    "/api/health",
    "/api/auth/token",
    "/docs",
    "/redoc",
    "/openapi.json",
}

AUTH_REQUIRED = JWT_SECRET is not None

# localhost + RFC 1918 LAN ranges (http or https, any port)
DEFAULT_ORIGIN_REGEX = (
    r"^https?://("
    r"localhost|127\.0\.0\.1|\[::1\]|"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r")(:\d+)?$"
)


def cors_settings() -> dict:
    """Keyword arguments for CORSMiddleware.

    Explicit comma-separated origins come from ``XWA_CORS_ORIGINS``; when unset,
    localhost and private LAN ranges are allowed via regex. Credentials are
    always disabled (auth travels as ``Authorization: Bearer``).
    """
    raw = (os.getenv("XWA_CORS_ORIGINS") or "").strip()
    settings: dict = {
        "allow_credentials": False,
        "allow_methods": ["*"],
        "allow_headers": ["*"],
    }
    if raw:
        settings["allow_origins"] = [o.strip() for o in raw.split(",") if o.strip()]
    else:
        settings["allow_origins"] = []
        settings["allow_origin_regex"] = DEFAULT_ORIGIN_REGEX
    return settings


def is_exempt(path: str) -> bool:
    return path in EXEMPT_PATHS


async def rate_limit_middleware(request: Request, call_next):
    if request.method == "OPTIONS" or is_exempt(request.url.path):
        return await call_next(request)

    client = request.client.host if request.client else "unknown"
    now = time.monotonic()
    hits = _hits[client]
    while hits and now - hits[0] > RATE_LIMIT_WINDOW:
        hits.popleft()
    if len(hits) >= RATE_LIMIT_MAX:
        return JSONResponse(
            status_code=429,
            content={
                "error": {
                    "code": "RATE_LIMITED",
                    "message": "Rate limit exceeded, try again later.",
                    "detail": {"limit_per_minute": RATE_LIMIT_MAX},
                    "retryable": True,
                }
            },
        )
    hits.append(now)
    return await call_next(request)


async def auth_middleware(request: Request, call_next):
    if not AUTH_REQUIRED or is_exempt(request.url.path):
        return await call_next(request)

    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return JSONResponse(
            status_code=401,
            content={
                "error": {
                    "code": "UNAUTHORIZED",
                    "message": "Missing bearer token.",
                    "detail": None,
                    "retryable": False,
                }
            },
        )
    if not validate_token(auth.removeprefix("Bearer ").strip()):
        return JSONResponse(
            status_code=401,
            content={
                "error": {
                    "code": "UNAUTHORIZED",
                    "message": "Invalid or expired token.",
                    "detail": None,
                    "retryable": False,
                }
            },
        )
    return await call_next(request)


def validate_token(token: str) -> bool:
    try:
        pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return True
    except pyjwt.PyJWTError:
        return False


def validate_ws_token(token: str | None) -> bool:
    """WebSocket clients cannot set headers, so the token travels as ?token=."""
    if not AUTH_REQUIRED:
        return True
    if not token:
        return False
    return validate_token(token)


def issue_token() -> str:
    now = int(time.time())
    return pyjwt.encode(
        {"sub": "kabuki-user", "iat": now, "exp": now + TOKEN_TTL_HOURS * 3600},
        JWT_SECRET,
        algorithm="HS256",
    )


def reset_rate_limiter() -> None:
    """Clear the in-memory counters (used by tests and operational resets)."""
    _hits.clear()
