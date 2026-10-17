"""Per-caller rate-limit for the user-list / directory endpoints (ID-53 / ID-6).

The list endpoints (``id_list_users`` → InternalUserListView, ``id_list_all_users``
→ AllUsersView, ``id_list_all_users_staff`` → AdminUserListView) are the highest-
value enumeration surface on shizuha-id. Row-scoping (ID-52) stops a caller from
seeing the whole population *per request*; this bounds the COST/abuse of repeated
list/search calls *per caller*, so the directory can't be scraped by hammering it.

Reuses the exact atomic Redis sliding-window-log mechanism as
``identity.tenant_rate_limit`` / ``identity.refresh_storm`` (single Lua:
ZADD / ZREMRANGEBYSCORE / ZCARD / PEXPIRE — race-free under concurrency), keyed
per authenticated caller. **Fail-OPEN** on any Redis/infra error: an abuse control
must never itself cause an outage. Kept as a dedicated module (not folded into the
tenant limiter) so the two controls have independent quotas/config and this one
can't perturb the PLAT-1331 tenant limiter.
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Optional

import redis
from django.conf import settings

logger = logging.getLogger(__name__)

_KEY_PREFIX = "shizuha-id:listusers-rl:"

# Atomic sliding-window-log: record this event, drop events older than the
# window, return the current in-window count (mirrors tenant_rate_limit / refresh_storm).
_WINDOW_LUA = """
redis.call('ZADD', KEYS[1], ARGV[1], ARGV[3])
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, tonumber(ARGV[1]) - tonumber(ARGV[2]))
local count = redis.call('ZCARD', KEYS[1])
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[2]))
return count
"""


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    count: int
    limit: int
    key: str


def _cfg_enabled() -> bool:
    return bool(getattr(settings, "USER_LIST_RATE_LIMIT_ENABLED", True))


def _cfg_limit() -> int:
    return int(getattr(settings, "USER_LIST_RATE_LIMIT_PER_WINDOW", 60))


def _cfg_window_s() -> int:
    return int(getattr(settings, "USER_LIST_RATE_LIMIT_WINDOW_S", 60))


_client_lock = threading.Lock()
_client: Optional[redis.Redis] = None
_script = None


def _get_client() -> redis.Redis:
    global _client, _script
    if _client is None:
        with _client_lock:
            if _client is None:
                url = getattr(
                    settings, "USER_LIST_RATE_LIMIT_REDIS_URL",
                    getattr(
                        settings, "TENANT_RATE_LIMIT_REDIS_URL",
                        getattr(
                            settings, "REFRESH_STORM_REDIS_URL",
                            getattr(settings, "CELERY_BROKER_URL", "redis://localhost:6379/2"),
                        ),
                    ),
                )
                _client = redis.Redis.from_url(url, decode_responses=True)
                _script = _client.register_script(_WINDOW_LUA)
    return _client


def reset_client() -> None:
    """Drop the cached client/script (tests inject a fakeredis client)."""
    global _client, _script
    _client = None
    _script = None


def set_client(client: Optional[redis.Redis]) -> None:
    """Inject a Redis client (tests). Pass None to reset to lazy config-driven."""
    global _client, _script
    if client is None:
        reset_client()
        return
    _client = client
    _script = client.register_script(_WINDOW_LUA)


def check(caller_key: str, *, now_ms: Optional[int] = None) -> RateDecision:
    """Record one list request against ``caller_key``; decide allow/deny.

    Fail-OPEN: on ANY Redis/infra error the request is allowed (count=0) so the
    limiter can never itself cause an outage.
    """
    limit = _cfg_limit()
    window_ms = _cfg_window_s() * 1000
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    member = f"{now_ms}:{uuid.uuid4().hex}"
    redis_key = f"{_KEY_PREFIX}{caller_key}"
    try:
        _get_client()
        count = int(_script(keys=[redis_key], args=[now_ms, window_ms, member]))
    except Exception:  # noqa: BLE001 — abuse control fails OPEN
        logger.warning("user-list rate-limit fail-open (redis error) for %s", caller_key, exc_info=True)
        return RateDecision(allowed=True, count=0, limit=limit, key=caller_key)
    return RateDecision(allowed=count <= limit, count=count, limit=limit, key=caller_key)


def enforce(request):
    """Return a DRF 429 Response if the authenticated caller exceeded the user-list
    quota, else ``None`` (proceed). No-op (None) when disabled or the caller is not
    authenticated. Never raises — fail-open on any internal error."""
    from rest_framework import status as drf_status
    from rest_framework.response import Response

    if not _cfg_enabled():
        return None
    user = getattr(request, "user", None)
    if user is None or not getattr(user, "is_authenticated", False):
        return None
    try:
        decision = check(f"user:{user.pk}")
    except Exception:  # noqa: BLE001 — never break the request path
        logger.warning("user-list rate-limit enforce fail-open", exc_info=True)
        return None
    if not decision.allowed:
        logger.info(
            "user-list rate-limit 429 for %s (%d/%d)",
            decision.key, decision.count, decision.limit,
        )
        resp = Response(
            {"detail": "Rate limit exceeded for user-list requests. Retry shortly."},
            status=drf_status.HTTP_429_TOO_MANY_REQUESTS,
        )
        resp["Retry-After"] = str(_cfg_window_s())
        return resp
    return None
