"""Signup abuse controls — Turnstile, rate limits, disposable mail, honeypot.

Password registration is still pending-admin until ALLOW_OPEN_REGISTRATION is
flipped. These checks exist so that flip does not mean "anyone can mint
thousands of accounts." They also run now, while the approval gate is on, so
the queue cannot be flooded.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from django.conf import settings
from django.core.cache import cache

from .auth_backoff import client_ip
from .canonicalization import normalize_email

logger = logging.getLogger(__name__)

TURNSTILE_SITEVERIFY = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'
GENERIC_DENIED = 'Could not create the account. Try again in a little while.'

# Common throwaway hosts. Not exhaustive — rate limits catch the rest.
_DISPOSABLE_DOMAINS = frozenset({
    'mailinator.com', 'guerrillamail.com', 'guerrillamail.net', 'sharklasers.com',
    'grr.la', 'guerrillamail.biz', 'guerrillamail.de', 'guerrillamail.org',
    'spam4.me', 'pokemail.net', 'trashmail.com', 'trashmail.de', 'trashmail.net',
    'yopmail.com', 'yopmail.fr', 'cool.fr.nf', 'jetable.org', 'nospam.ze.tc',
    'tempmail.com', 'temp-mail.org', 'temp-mail.io', 'tmpmail.org', 'tmpmail.net',
    '10minutemail.com', '10minutemail.net', 'minutemail.com', 'moakt.com',
    'dispostable.com', 'mailnesia.com', 'maildrop.cc', 'discard.email',
    'mailcatch.com', 'getnada.com', 'nada.email', 'emailondeck.com',
    'fakeinbox.com', 'throwawaymail.com', 'trashinbox.com', 'mytemp.email',
    'tempail.com', 'tempr.email', 'emailfake.com', 'crazymailing.com',
    'inboxkitten.com', 'mailnull.com', 'spamgourmet.com', 'guerrillamailblock.com',
    'mailforspam.com', 'spamobox.com', 'tmpeml.com', 'dropmail.me',
})

_MAJOR_MAIL_DOMAINS = frozenset({
    'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com',
    'yahoo.com', 'icloud.com', 'me.com', 'proton.me', 'protonmail.com',
    'zoho.com', 'aol.com', 'gmx.com', 'gmx.net', 'fastmail.com',
})


def turnstile_sitekey() -> str:
    return (getattr(settings, 'TURNSTILE_SITE_KEY', '') or '').strip()


def turnstile_secret() -> str:
    return (getattr(settings, 'TURNSTILE_SECRET', '') or '').strip()


def captcha_required() -> bool:
    forced = getattr(settings, 'TURNSTILE_REQUIRED', None)
    if forced is not None:
        return bool(forced)
    return bool(turnstile_secret())


def open_registration_enabled() -> bool:
    return bool(getattr(settings, 'ALLOW_OPEN_REGISTRATION', False))


def rate_limits_enabled() -> bool:
    return bool(getattr(settings, 'SIGNUP_RATE_LIMITS_ENABLED', False))


def signup_config() -> dict:
    required = captcha_required()
    sitekey = turnstile_sitekey()
    return {
        'captcha': {
            'provider': 'turnstile' if sitekey or required else '',
            'sitekey': sitekey,
            'required': required,
        },
        'open_registration': open_registration_enabled(),
        'approval_required': not open_registration_enabled(),
    }


def email_domain(email: str) -> str:
    normalized = normalize_email(email)
    if '@' not in normalized:
        return ''
    return normalized.rsplit('@', 1)[-1]


def qa_fixture_signup_domain() -> str:
    return (getattr(settings, 'QA_FIXTURE_SIGNUP_DOMAIN', '') or '').strip().lower()


def is_qa_fixture_email(email: str) -> bool:
    """True when the email belongs to the QA fixture signup domain (HIVE-1987).

    Fixture emails skip the Turnstile captcha (honeypot + rate limits still
    apply) and are auto-approved on registration so non-staff QA seats can mint
    a fresh blank-slate test user each cycle without operator/staff approval.
    """
    domain = qa_fixture_signup_domain()
    if not domain:
        return False
    return email_domain(email) == domain


def is_disposable_email(email: str) -> bool:
    domain = email_domain(email)
    if not domain:
        return True
    if domain in _DISPOSABLE_DOMAINS:
        return True
    # plus-address farms on disposable-like second-level hosts
    parts = domain.split('.')
    if len(parts) >= 3 and '.'.join(parts[-2:]) in _DISPOSABLE_DOMAINS:
        return True
    return False


def _int_setting(name: str, default: int) -> int:
    try:
        return int(getattr(settings, name, default) or default)
    except (TypeError, ValueError):
        return default


def _subnet_key(ip: str) -> str:
    try:
        addr = ipaddress.ip_address((ip or '').strip())
    except ValueError:
        return 'unknown'
    if isinstance(addr, ipaddress.IPv4Address):
        net = ipaddress.ip_network(f'{addr}/24', strict=False)
        return str(net.network_address)
    net = ipaddress.ip_network(f'{addr}/64', strict=False)
    return str(net.network_address)


def _incr(key: str, window_s: int) -> int:
    try:
        return int(cache.incr(key))
    except ValueError:
        cache.set(key, 1, window_s)
        return 1


@dataclass(frozen=True)
class RateLimitHit:
    dimension: str
    count: int
    limit: int


def check_signup_rate(request, email: str) -> RateLimitHit | None:
    """Return a hit when this request would exceed a signup budget. Does not increment."""
    if not rate_limits_enabled():
        return None
    window = _int_setting('SIGNUP_WINDOW_SECONDS', 3600)
    ip = client_ip(request)
    subnet = _subnet_key(ip)
    domain = email_domain(email)
    checks = [
        ('ip', f'signup:ip:{ip}', _int_setting('SIGNUP_IP_MAX_PER_WINDOW', 5)),
        ('subnet', f'signup:net:{subnet}', _int_setting('SIGNUP_SUBNET_MAX_PER_WINDOW', 20)),
    ]
    if domain and domain not in _MAJOR_MAIL_DOMAINS:
        checks.append((
            'domain',
            f'signup:dom:{domain}',
            _int_setting('SIGNUP_DOMAIN_MAX_PER_WINDOW', 8),
        ))
    for dimension, key, limit in checks:
        current = int(cache.get(key) or 0)
        if current >= limit:
            return RateLimitHit(dimension=dimension, count=current, limit=limit)
    return None


def record_signup(request, email: str) -> None:
    if not rate_limits_enabled():
        return
    window = _int_setting('SIGNUP_WINDOW_SECONDS', 3600)
    ip = client_ip(request)
    subnet = _subnet_key(ip)
    domain = email_domain(email)
    _incr(f'signup:ip:{ip}', window)
    _incr(f'signup:net:{subnet}', window)
    if domain and domain not in _MAJOR_MAIL_DOMAINS:
        _incr(f'signup:dom:{domain}', window)


def verify_turnstile(token: str, remote_ip: str = '') -> tuple[bool, str]:
    secret = turnstile_secret()
    if not secret:
        if captcha_required():
            return False, 'captcha_not_configured'
        return True, 'captcha_not_configured'
    token = (token or '').strip()
    if not token:
        return False, 'missing_token'
    body = urllib.parse.urlencode({
        'secret': secret,
        'response': token,
        **({'remoteip': remote_ip} if remote_ip and remote_ip != 'unknown' else {}),
    }).encode()
    req = urllib.request.Request(
        TURNSTILE_SITEVERIFY,
        data=body,
        method='POST',
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode() or '{}')
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError) as exc:
        logger.warning('turnstile siteverify failed: %s', exc)
        return False, 'siteverify_error'
    if data.get('success') is True:
        return True, 'ok'
    return False, ','.join(str(x) for x in (data.get('error-codes') or ['rejected']))


def honeypot_tripped(request) -> bool:
    data = getattr(request, 'data', None)
    if not isinstance(data, dict):
        return False
    bait = str(data.get('website') or data.get('company_url') or '').strip()
    return bool(bait)


def reject_signup(request, *, email: str = '', captcha_token: str = '', require_captcha: bool = True) -> dict | None:
    """If the signup must be refused, return a JSON-serializable error payload.

    Callers should respond 400 with GENERIC_DENIED so bots cannot probe which
    control fired. Logs carry the real reason.
    """
    if honeypot_tripped(request):
        logger.info('signup honeypot tripped ip=%s', client_ip(request))
        return {'error': GENERIC_DENIED, 'code': 'signup_denied'}
    if email and is_disposable_email(email):
        logger.info('signup disposable email ip=%s domain=%s', client_ip(request), email_domain(email))
        return {'error': GENERIC_DENIED, 'code': 'signup_denied'}
    hit = check_signup_rate(request, email)
    if hit is not None:
        logger.info(
            'signup rate-limited dim=%s count=%s/%s ip=%s',
            hit.dimension, hit.count, hit.limit, client_ip(request),
        )
        return {'error': GENERIC_DENIED, 'code': 'signup_denied'}
    if require_captcha and captcha_required() and not is_qa_fixture_email(email):
        ok, reason = verify_turnstile(captcha_token, client_ip(request))
        if not ok:
            logger.info('signup captcha failed reason=%s ip=%s', reason, client_ip(request))
            return {'error': GENERIC_DENIED, 'code': 'signup_denied'}
    if is_qa_fixture_email(email):
        logger.info('signup qa-fixture bypass domain=%s ip=%s', email_domain(email), client_ip(request))
    return None
