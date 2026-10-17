"""Per-account and per-IP auth backoff helpers.

The security property is deliberately two-dimensional: account identifiers are
hashed into cache keys so rotating/spoofing client IPs cannot bypass account
lockout, while IP keys bound spray attacks across many accounts.
"""
from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass

from django.conf import settings
from django.core.cache import cache


@dataclass(frozen=True)
class BackoffConfig:
    scope: str
    max_attempts_setting: str
    window_seconds_setting: str
    base_lockout_seconds_setting: str
    max_lockout_seconds_setting: str
    default_max_attempts: int = 5
    default_window_seconds: int = 15 * 60
    default_base_lockout_seconds: int = 60
    default_max_lockout_seconds: int = 15 * 60
    ip_exempt_cidrs_setting: str = ''
    trusted_proxy_cidrs_setting: str = ''


def norm_identifier(identifier: str) -> str:
    return (identifier or '').strip().lower()


def identifier_hash(identifier: str) -> str:
    return hashlib.sha256(norm_identifier(identifier).encode('utf-8')).hexdigest()[:24]


def client_ip(request) -> str:
    # Preserve current deployment behaviour (DRF's get_ident posture) while relying
    # on the independent account key for spoof-resistant lockout.
    forwarded = (request.META.get('HTTP_X_FORWARDED_FOR') or '').split(',')[0].strip()
    return forwarded or request.META.get('REMOTE_ADDR') or 'unknown'


def _split_cidrs(raw: str) -> tuple[ipaddress._BaseNetwork, ...]:
    cidrs = []
    for item in (raw or '').split(','):
        item = item.strip()
        if not item:
            continue
        try:
            cidrs.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return tuple(cidrs)


def _ip_in_cidrs(ip: str, cidrs: tuple[ipaddress._BaseNetwork, ...]) -> bool:
    try:
        addr = ipaddress.ip_address((ip or '').strip())
    except ValueError:
        return False
    return any(addr in cidr for cidr in cidrs)


def _first_forwarded(request) -> str:
    return (request.META.get('HTTP_X_FORWARDED_FOR') or '').split(',')[0].strip()


def _remote_addr(request) -> str:
    return (request.META.get('REMOTE_ADDR') or '').strip()


def pii_hash(value: str) -> str:
    return hashlib.sha256(norm_identifier(value).encode('utf-8')).hexdigest()[:12]


class AuthBackoff:
    def __init__(self, config: BackoffConfig):
        self.config = config

    def max_attempts(self) -> int:
        return int(getattr(settings, self.config.max_attempts_setting, self.config.default_max_attempts))

    def window_seconds(self) -> int:
        return int(getattr(settings, self.config.window_seconds_setting, self.config.default_window_seconds))

    def base_lockout_seconds(self) -> int:
        return int(getattr(settings, self.config.base_lockout_seconds_setting, self.config.default_base_lockout_seconds))

    def max_lockout_seconds(self) -> int:
        return int(getattr(settings, self.config.max_lockout_seconds_setting, self.config.default_max_lockout_seconds))

    def ip_exempt_cidrs(self) -> tuple[ipaddress._BaseNetwork, ...]:
        if not self.config.ip_exempt_cidrs_setting:
            return ()
        return _split_cidrs(str(getattr(settings, self.config.ip_exempt_cidrs_setting, '')))

    def trusted_proxy_cidrs(self) -> tuple[ipaddress._BaseNetwork, ...]:
        if not self.config.trusted_proxy_cidrs_setting:
            return ()
        return _split_cidrs(str(getattr(settings, self.config.trusted_proxy_cidrs_setting, '')))

    def _account_key(self, kind: str, identifier: str) -> str:
        return f'{self.config.scope}:acct:{kind}:{identifier_hash(identifier)}'

    def _ip_key(self, kind: str, request) -> str:
        return f'{self.config.scope}:ip:{kind}:{client_ip(request)}'

    def _skip_ip_dimension(self, request) -> bool:
        """Whether this request is allowed to skip the IP-dimension limiter.

        This is intentionally narrower than ``client_ip``. A spoofed
        X-Forwarded-For value is trusted only when the immediate peer is in a
        configured trusted-proxy CIDR. Direct requests from an exempt remote addr
        also qualify for non-proxied internal paths.
        """
        exempt = self.ip_exempt_cidrs()
        if not exempt:
            return False
        remote = _remote_addr(request)
        if _ip_in_cidrs(remote, exempt):
            return True
        forwarded = _first_forwarded(request)
        if not forwarded:
            return False
        trusted_proxies = self.trusted_proxy_cidrs()
        return bool(trusted_proxies and _ip_in_cidrs(remote, trusted_proxies) and _ip_in_cidrs(forwarded, exempt))

    def _lock_keys(self, request, identifier: str) -> tuple[str, ...]:
        keys = [self._account_key('lock', identifier)]
        if not self._skip_ip_dimension(request):
            keys.append(self._ip_key('lock', request))
        return tuple(keys)

    def _failure_keys(self, request, identifier: str) -> tuple[str, ...]:
        keys = [self._account_key('fail', identifier)]
        if not self._skip_ip_dimension(request):
            keys.append(self._ip_key('fail', request))
        return tuple(keys)

    def _ttl_or_value(self, key: str) -> int:
        ttl = cache.ttl(key) if hasattr(cache, 'ttl') else None
        if ttl is not None and ttl > 0:
            return int(ttl)
        return int(cache.get(key) or 0)

    def lockout_remaining(self, request, identifier: str) -> int:
        return max(self._ttl_or_value(key) for key in self._lock_keys(request, identifier))

    def is_locked(self, request, identifier: str) -> bool:
        return any(bool(cache.get(key)) for key in self._lock_keys(request, identifier))

    def _record_key_failure(self, key: str) -> tuple[int, int]:
        try:
            failures = cache.incr(key)
        except ValueError:
            cache.set(key, 1, self.window_seconds())
            failures = 1
        lockout_s = 0
        if failures >= self.max_attempts():
            exponent = max(0, failures - self.max_attempts())
            lockout_s = min(self.max_lockout_seconds(), self.base_lockout_seconds() * (2 ** exponent))
        return int(failures), int(lockout_s)

    def record_failure(self, request, identifier: str) -> tuple[int, int]:
        """Record an attempt for both account and IP dimensions.

        Returns ``(max_failures, max_lockout_s)`` across both dimensions. If either
        dimension crosses the threshold, both the account and IP lock markers are
        set to the resulting maximum lockout so future checks fail closed.
        """
        results = [self._record_key_failure(key) for key in self._failure_keys(request, identifier)]
        failures = max(result[0] for result in results)
        lockout_s = max(result[1] for result in results)
        if lockout_s:
            for key in self._lock_keys(request, identifier):
                cache.set(key, lockout_s, lockout_s)
        return failures, lockout_s

    def clear(self, request, identifier: str) -> None:
        for key in (*self._failure_keys(request, identifier), *self._lock_keys(request, identifier)):
            cache.delete(key)
