"""Password-reset non-enumeration and reset-request throttling helpers."""
from __future__ import annotations

import secrets
import logging
import threading
import time

from django.conf import settings

from .auth_backoff import AuthBackoff, BackoffConfig
from .services import send_password_reset_email, EmailServiceError

logger = logging.getLogger(__name__)

GENERIC_RESET_MESSAGE = 'If an account exists with this email, you will receive a reset link.'

_BACKOFF = AuthBackoff(BackoffConfig(
    scope='pwreset',
    max_attempts_setting='PASSWORD_RESET_MAX_ATTEMPTS',
    window_seconds_setting='PASSWORD_RESET_WINDOW_SECONDS',
    base_lockout_seconds_setting='PASSWORD_RESET_BASE_LOCKOUT_SECONDS',
    max_lockout_seconds_setting='PASSWORD_RESET_MAX_LOCKOUT_SECONDS',
))


def min_response_seconds() -> float:
    return float(getattr(settings, 'PASSWORD_RESET_MIN_RESPONSE_SECONDS', 0.25))


def is_locked(request, identifier: str) -> bool:
    return _BACKOFF.is_locked(request, identifier)


def lockout_remaining(request, identifier: str) -> int:
    return _BACKOFF.lockout_remaining(request, identifier)


def record_request(request, identifier: str) -> tuple[int, int]:
    return _BACKOFF.record_failure(request, identifier)


def pad_response(started_at: float) -> None:
    remaining = min_response_seconds() - (time.monotonic() - started_at)
    if remaining > 0:
        time.sleep(remaining)


def dummy_reset_work() -> None:
    """Burn roughly comparable local crypto work for the no-account branch.

    We deliberately do NOT send an account-creation email for unknown reset
    requests: that branch was a separate behaviour and abuse/enumeration wrinkle.
    The outward response remains the generic reset message.
    """
    secrets.token_urlsafe(32)


def _send_password_reset_email_worker(user, reset_url: str) -> None:
    try:
        send_password_reset_email(user, reset_url)
        logger.info("Password reset email queued worker completed")
    except EmailServiceError:
        logger.error("Failed to send queued reset email for active account")


def send_password_reset_email_async(user, reset_url: str) -> threading.Thread:
    """Send reset email off the response path.

    The request handler must not perform account-existence-dependent external
    mail I/O before returning, otherwise mail latency becomes an enumeration
    oracle. A daemon thread keeps the HTTP response path local and uniform.
    """
    thread = threading.Thread(
        target=_send_password_reset_email_worker,
        args=(user, reset_url),
        name='password-reset-email',
        daemon=True,
    )
    thread.start()
    return thread
