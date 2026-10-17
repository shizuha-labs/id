"""Login-time two-factor helpers (PLAT-493 / SEC-2)."""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from django.conf import settings
from django.core import signing
from django.core.cache import cache
from django.utils import timezone

PENDING_PURPOSE = 'login-2fa'
_SIGN_SALT = 'identity.login_2fa.pending.v1'


@dataclass(frozen=True)
class PendingLogin:
    user_id: int
    jti: str


def _cache_key(jti: str) -> str:
    return f'login2fa:pending:{jti}'


def pending_ttl_seconds() -> int:
    return int(getattr(settings, 'TWOFA_LOGIN_PENDING_TTL_SECONDS', 300))


def mint_pending_login_token(user) -> tuple[str, str, int]:
    """Mint a short-lived, single-purpose token after password auth."""
    jti = uuid.uuid4().hex
    ttl = pending_ttl_seconds()
    payload = {
        'purpose': PENDING_PURPOSE,
        'user_id': int(user.pk),
        'jti': jti,
        'amr': ['pwd'],
    }
    token = signing.dumps(payload, salt=_SIGN_SALT, compress=True)
    expires_at = int((timezone.now() + timezone.timedelta(seconds=ttl)).timestamp())
    cache.set(_cache_key(jti), {'user_id': int(user.pk), 'created_at': timezone.now().isoformat()}, ttl)
    return token, jti, expires_at


def load_pending_login_token(token: str) -> PendingLogin | None:
    try:
        payload: dict[str, Any] = signing.loads(token, salt=_SIGN_SALT, max_age=pending_ttl_seconds())
    except signing.BadSignature:
        return None
    if payload.get('purpose') != PENDING_PURPOSE:
        return None
    user_id = payload.get('user_id')
    jti = payload.get('jti')
    if not user_id or not jti:
        return None
    marker = cache.get(_cache_key(jti))
    if not marker or int(marker.get('user_id')) != int(user_id):
        return None
    return PendingLogin(user_id=int(user_id), jti=str(jti))


def consume_pending_login_token(pending: PendingLogin) -> bool:
    """Consume the pending token once using cache.add as the atomic claim."""
    key = _cache_key(pending.jti)
    if not cache.get(key):
        return False
    used_key = f'login2fa:used:{pending.jti}'
    if not cache.add(used_key, '1', pending_ttl_seconds()):
        return False
    cache.delete(key)
    return True


def failure_cache_key(pending: PendingLogin) -> str:
    return f'login2fa:failures:{pending.user_id}:{pending.jti}'


def max_attempts() -> int:
    return int(getattr(settings, 'TWOFA_LOGIN_MAX_ATTEMPTS', 5))


def attempts_exhausted(pending: PendingLogin) -> bool:
    return int(cache.get(failure_cache_key(pending)) or 0) >= max_attempts()


def record_failure(pending: PendingLogin) -> int:
    from .invariants import record_token_event
    record_token_event('twofa', 'failure')
    key = failure_cache_key(pending)
    ttl = pending_ttl_seconds()
    try:
        failures = cache.incr(key)
    except ValueError:
        cache.set(key, 1, ttl)
        failures = 1
    return int(failures)


def clear_failures(pending: PendingLogin) -> None:
    cache.delete(failure_cache_key(pending))


def challenge_cache_key(pending: PendingLogin, device_id: int) -> str:
    return f'login2fa:webauthn:{pending.jti}:{device_id}'
