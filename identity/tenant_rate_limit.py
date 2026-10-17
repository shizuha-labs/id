"""Per-tenant rate-limit middleware (PLAT-1331 Part B / PLAT-1323 pilot).

Availability-isolation backstop: a shared per-tenant request quota so one
tenant cannot exhaust shared Redis/DB/CPU for everyone else. Generalizes the
Cortex per-key RPM pattern (CTX-50/HIVE-350) to a platform tenant key and
reuses the same atomic Redis sliding-window-log mechanism as
``identity.refresh_storm`` (single Lua: ZADD / ZREMRANGEBYSCORE / ZCARD /
PEXPIRE) so the count is race-free under concurrency.

Design (per PLAT-1331 jun's scoped plan):
  - Sliding-window log keyed per tenant: ``shizuha-id:tenant-rl:<tenant_key>``.
  - Tenant key = the request's target org only when the authenticated
    principal is verified as a member of that org (``X-Organization-ID``
    header + membership claim/attribute), else the authenticated user. This
    prevents a caller from charging a victim org's quota by forging the org
    header. Reversible to strict-org-only via a future config knob.
  - Runs AFTER AuthenticationMiddleware so the principal is resolved.
  - **Fail-open on any Redis/infra error**: an availability-isolation control
    must never itself cause an outage — a limiter that hard-fails would turn a
    Redis blip into a full 500 storm. Errors are logged, the request proceeds.
  - **Default OFF** (``TENANT_RATE_LIMIT_ENABLED=false``) until the pilot
    explicitly enables it per-environment.
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
from django.http import JsonResponse

logger = logging.getLogger(__name__)

_KEY_PREFIX = "shizuha-id:tenant-rl:"

# Atomic sliding-window-log: record this event, drop events older than the
# window, return the current in-window count. Mirrors refresh_storm's window
# (minus the storm-latch — a limiter only needs the count vs the quota).
#   KEYS[1] = per-tenant events sorted-set (score = event ms, member = unique)
#   ARGV[1] = now_ms   ARGV[2] = window_ms   ARGV[3] = unique member id
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
    tenant_key: str


def _cfg_enabled() -> bool:
    return bool(getattr(settings, "TENANT_RATE_LIMIT_ENABLED", False))


def _cfg_limit() -> int:
    return int(getattr(settings, "TENANT_RATE_LIMIT_RPM", 600))


def _cfg_window_s() -> int:
    return int(getattr(settings, "TENANT_RATE_LIMIT_WINDOW_S", 60))


_client_lock = threading.Lock()
_client: Optional[redis.Redis] = None
_script = None


def _get_client() -> redis.Redis:
    global _client, _script
    if _client is None:
        with _client_lock:
            if _client is None:
                url = getattr(
                    settings,
                    "TENANT_RATE_LIMIT_REDIS_URL",
                    getattr(
                        settings,
                        "REFRESH_STORM_REDIS_URL",
                        getattr(settings, "CELERY_BROKER_URL", "redis://localhost:6379/2"),
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


def check(tenant_key: str, *, now_ms: Optional[int] = None) -> RateDecision:
    """Record one request against ``tenant_key`` and decide allow/deny.

    Fail-open: on ANY Redis/infra error the request is allowed (count=0) so the
    limiter can never itself cause an outage.
    """
    limit = _cfg_limit()
    window_ms = _cfg_window_s() * 1000
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    member = f"{now_ms}:{uuid.uuid4().hex}"
    redis_key = f"{_KEY_PREFIX}{tenant_key}"
    try:
        _get_client()
        count = int(_script(keys=[redis_key], args=[now_ms, window_ms, member]))
    except Exception:  # noqa: BLE001 — availability control fails OPEN
        logger.warning("tenant rate-limit fail-open (redis error) for %s", tenant_key, exc_info=True)
        return RateDecision(allowed=True, count=0, limit=limit, tenant_key=tenant_key)
    return RateDecision(allowed=count <= limit, count=count, limit=limit, tenant_key=tenant_key)


def _membership_map_from(value) -> set[int]:
    """Normalize org-membership shapes from JWT claims/session test doubles."""
    if not value:
        return set()
    if isinstance(value, dict):
        raw_ids = value.keys()
    elif isinstance(value, (list, tuple, set)):
        raw_ids = value
    else:
        raw_ids = [value]
    out = set()
    for raw in raw_ids:
        try:
            out.add(int(raw))
        except (TypeError, ValueError):
            continue
    return out


def _verified_org_memberships(request, user) -> set[int]:
    """Best-effort verified org set for the authenticated principal.

    Accepts the shapes emitted by shizuha-id JWT/OIDC claims
    (``organization_memberships`` as a dict keyed by org id) and simple session
    or test attributes on ``request.user``. Absence means *not verified* for
    org-header metering, so callers fall back to their user bucket.
    """
    candidates = []
    auth = getattr(request, "auth", None)
    if isinstance(auth, dict):
        candidates.append(auth.get("organization_memberships"))
        candidates.append(auth.get("org_ids"))
    elif auth is not None:
        try:
            candidates.append(auth.get("organization_memberships"))
            candidates.append(auth.get("org_ids"))
        except Exception:  # noqa: BLE001 - token objects vary by backend
            pass
    for attr in ("organization_memberships", "org_memberships", "org_ids", "organizations"):
        candidates.append(getattr(user, attr, None))
    memberships = set()
    for value in candidates:
        memberships |= _membership_map_from(value)
    # Some service/session users carry a single active org id rather than the
    # full membership map; accept it as verified for that one org only.
    for attr in ("organization_id", "org_id"):
        try:
            val = getattr(user, attr, None)
            if val is not None:
                memberships.add(int(val))
        except (TypeError, ValueError):
            pass
    return memberships


def resolve_tenant_key(request) -> Optional[str]:
    """The shared-resource consumer this request should be metered against.

    A valid ``X-Organization-ID`` meters per org only when the authenticated
    principal is verified as a member of that org. Forged/foreign/bad org
    headers fall back to the caller's user bucket so one tenant cannot exhaust
    another tenant's quota. Unidentified (pre-auth) requests return None → not
    metered (pre-auth abuse is handled by the auth-backoff/refresh-storm layer).
    """
    user = getattr(request, "user", None)
    if user is None or not getattr(user, "is_authenticated", False):
        return None

    raw_org = request.META.get("HTTP_X_ORGANIZATION_ID")
    if raw_org:
        try:
            org_id = int(raw_org)
        except (TypeError, ValueError):
            org_id = None
        if org_id is not None and org_id in _verified_org_memberships(request, user):
            return f"org:{org_id}"

    return f"user:{user.pk}"


class TenantRateLimitMiddleware:
    """Return 429 when a tenant exceeds its per-window request quota.

    Placed AFTER AuthenticationMiddleware so ``request.user`` is resolved.
    Entirely inert unless ``TENANT_RATE_LIMIT_ENABLED`` is true, and fail-open
    on any internal error."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not _cfg_enabled():
            return self.get_response(request)
        try:
            tenant_key = resolve_tenant_key(request)
            if tenant_key is not None:
                decision = check(tenant_key)
                if not decision.allowed:
                    logger.info(
                        "tenant rate-limit 429 for %s (%d/%d)",
                        decision.tenant_key, decision.count, decision.limit,
                    )
                    resp = JsonResponse(
                        {"detail": "Rate limit exceeded for this tenant. Retry shortly."},
                        status=429,
                    )
                    resp["Retry-After"] = str(_cfg_window_s())
                    return resp
        except Exception:  # noqa: BLE001 — never let the limiter break the request path
            logger.warning("tenant rate-limit middleware fail-open", exc_info=True)
        return self.get_response(request)
