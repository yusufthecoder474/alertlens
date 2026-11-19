"""API-key auth + simple in-memory rate limiting (429 on excess).

Key comparison uses ``hmac.compare_digest`` (constant time). The expected
key comes from ``api.config.settings`` — the only place config is read.
"""
import hmac
import time
from collections import defaultdict

from fastapi import Header, HTTPException

from api.config import settings

_requests: dict[str, list[float]] = defaultdict(list)


def reset_rate_limit() -> None:
    """Clear rate-limit counters (used by tests)."""
    _requests.clear()


def api_key_auth(x_api_key: str | None = Header(default=None)) -> str:
    """Require a valid X-API-Key header; missing/wrong key -> 401."""
    expected = settings.api_key
    if not x_api_key or not expected or not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return x_api_key


def check_rate_limit(key: str) -> None:
    """Allow RATE_LIMIT_PER_MINUTE requests per key per rolling minute."""
    limit = settings.rate_limit_per_minute
    now = time.time()
    window = [t for t in _requests[key] if now - t < 60]
    if len(window) >= limit:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    window.append(now)
    _requests[key] = window
