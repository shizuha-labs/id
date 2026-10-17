"""Password-login brute-force controls for PLAT-495 / SEC-4."""
from __future__ import annotations

from django.contrib.auth import get_user_model

from .auth_backoff import AuthBackoff, BackoffConfig, norm_identifier

_BACKOFF = AuthBackoff(BackoffConfig(
    scope='loginpwd',
    max_attempts_setting='LOGIN_PASSWORD_MAX_ATTEMPTS',
    window_seconds_setting='LOGIN_PASSWORD_WINDOW_SECONDS',
    base_lockout_seconds_setting='LOGIN_PASSWORD_BASE_LOCKOUT_SECONDS',
    max_lockout_seconds_setting='LOGIN_PASSWORD_MAX_LOCKOUT_SECONDS',
    ip_exempt_cidrs_setting='LOGIN_PASSWORD_IP_EXEMPT_CIDRS',
    trusted_proxy_cidrs_setting='LOGIN_PASSWORD_TRUSTED_PROXY_CIDRS',
))


def max_attempts() -> int:
    return _BACKOFF.max_attempts()


def window_seconds() -> int:
    return _BACKOFF.window_seconds()


def base_lockout_seconds() -> int:
    return _BACKOFF.base_lockout_seconds()


def max_lockout_seconds() -> int:
    return _BACKOFF.max_lockout_seconds()


def account_identifier(identifier: str) -> str:
    """Return a stable throttle key for an existing account.

    Login accepts either username or email. Using the submitted string directly
    gives the same account multiple per-account budgets (e.g. ``alice`` vs
    ``alice@example.com``), so resolve known users to their stable primary key.
    Unknown identifiers still receive a deterministic input key so abusive
    attempts are throttled without revealing whether the account exists.
    """
    normalized = norm_identifier(identifier)
    if not normalized:
        return 'input:'

    User = get_user_model()
    user = User.objects.filter(username__iexact=normalized).only('pk').first()
    if user is None:
        user = User.objects.filter(email__iexact=normalized).only('pk').first()
    if user:
        return f'user:{user.pk}'
    return f'input:{normalized}'


def lockout_remaining(request, identifier: str) -> int:
    return _BACKOFF.lockout_remaining(request, identifier)


def is_locked(request, identifier: str) -> bool:
    return _BACKOFF.is_locked(request, identifier)


def record_failure(request, identifier: str) -> tuple[int, int]:
    """Record a failed password attempt. Returns (failures, lockout_s)."""
    from .invariants import record_token_event
    record_token_event('password', 'failure')
    return _BACKOFF.record_failure(request, identifier)


def clear(request, identifier: str) -> None:
    _BACKOFF.clear(request, identifier)
