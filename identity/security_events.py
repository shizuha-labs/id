"""PLAT-4133: emit sanitized boundary-denial events to Connect SIEM-lite."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import time
import uuid

import requests
import redis
from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

_SAFE_ID_RE = re.compile(r'^[A-Za-z0-9_.:-]{1,128}$')
_METRIC_OUTCOMES = (
    'success',
    'disabled',
    'missing_secret',
    'unauthenticated_actor',
    'invalid_actor',
    'non_202',
    'timeout',
    'exception',
)
_METRIC_KEY = 'id:metrics:boundary_security_event:{outcome}'


def _metrics_redis_client():
    url = getattr(settings, 'CONNECT_SECURITY_EVENT_METRICS_REDIS_URL', '') or getattr(
        settings, 'CELERY_BROKER_URL', 'redis://redis:6379/2',
    )
    return redis.Redis.from_url(
        url,
        decode_responses=True,
        socket_connect_timeout=0.25,
        socket_timeout=0.25,
    )


def record_boundary_event_outcome(outcome: str) -> bool:
    """Persist one bounded producer outcome for independent Prometheus alerting."""
    outcome = outcome if outcome in _METRIC_OUTCOMES else 'exception'
    try:
        _metrics_redis_client().incr(_METRIC_KEY.format(outcome=outcome))
        return True
    except Exception:
        logger.exception('PLAT-4133 failed to persist boundary producer metric outcome=%s', outcome)
        return False


def render_boundary_event_metrics() -> str:
    counts = None
    probe_errors = 0
    try:
        client = _metrics_redis_client()
        values = client.mget([_METRIC_KEY.format(outcome=value) for value in _METRIC_OUTCOMES])
        parsed_counts = {outcome: 0 for outcome in _METRIC_OUTCOMES}
        parsed_counts.update({
            outcome: int(raw or 0)
            for outcome, raw in zip(_METRIC_OUTCOMES, values)
        })
        counts = parsed_counts
    except Exception:
        probe_errors = 1
        logger.exception('PLAT-4133 failed to collect boundary producer metrics')
    lines = []
    if counts is not None:
        lines.extend([
            '# HELP platform_boundary_event_producer_total Boundary-denial producer outcomes persisted by service.',
            '# TYPE platform_boundary_event_producer_total counter',
        ])
        lines.extend(
            f'platform_boundary_event_producer_total{{service="id",outcome="{outcome}"}} {counts[outcome]}'
            for outcome in _METRIC_OUTCOMES
        )
    lines.extend([
        '# HELP platform_boundary_event_producer_probe_errors Producer metric backend collection errors.',
        '# TYPE platform_boundary_event_producer_probe_errors gauge',
        f'platform_boundary_event_producer_probe_errors{{service="id"}} {probe_errors}',
    ])
    return '\n'.join(lines) + '\n'


def _org_ids(source) -> list[int]:
    ids = set()
    if isinstance(source, dict):
        source = source.keys()
    if isinstance(source, (list, tuple, set, dict)):
        for value in list(source)[:32]:
            try:
                parsed = int(value)
            except (TypeError, ValueError):
                continue
            if parsed > 0:
                ids.add(parsed)
    return sorted(ids)


def _request_org_ids(request) -> list[int]:
    user = getattr(request, 'user', None)
    ids = set(_org_ids(getattr(user, 'organization_memberships', {}) or {}))
    auth = getattr(request, 'auth', None)
    if not ids and isinstance(auth, dict):
        for key in ('organization_memberships', 'organization_ids', 'org_ids'):
            ids.update(_org_ids(auth.get(key)))
        for key in ('organization_id', 'org_id'):
            ids.update(_org_ids([auth.get(key)]))
    return sorted(ids)


def _correlation_id(request) -> str:
    headers = getattr(request, 'headers', {}) or {}
    value = str(headers.get('X-Correlation-ID') or headers.get('X-Request-ID') or '').strip()
    if _SAFE_ID_RE.fullmatch(value):
        return value
    return str(uuid.uuid4())


def emit_boundary_denial(
    *, request, service: str, operation: str, reason: str,
    target_org_id=None, source_org_ids=None,
) -> bool:
    """Synchronously enqueue one bounded event; never change the caller's 403."""
    try:
        if not bool(getattr(settings, 'CONNECT_SECURITY_EVENT_EMIT_ENABLED', True)):
            record_boundary_event_outcome('disabled')
            return False
        secret = getattr(settings, 'CONNECT_SECURITY_EVENT_ORIGIN_SECRET', '') or ''
        if not secret:
            record_boundary_event_outcome('missing_secret')
            logger.warning('PLAT-4133 boundary event secret is not configured')
            return False

        user = getattr(request, 'user', None)
        if not user or not getattr(user, 'is_authenticated', False):
            record_boundary_event_outcome('unauthenticated_actor')
            return False
        actor_user_id = int(getattr(user, 'id', 0) or 0)
        if actor_user_id <= 0:
            record_boundary_event_outcome('invalid_actor')
            return False
        actor_username = str(
            getattr(user, 'username', '') or getattr(user, 'email', '') or actor_user_id
        )[:150]
        route = operation
        resolver_match = getattr(request, 'resolver_match', None)
        if resolver_match is not None:
            route = getattr(resolver_match, 'view_name', '') or getattr(resolver_match, 'route', '') or route

        payload = {
            'specversion': '1.0',
            'id': str(uuid.uuid4()),
            'source': f'shizuha://{service}',
            'type': 'platform.boundary_denial',
            'time': timezone.now().isoformat(),
            'data': {
                'service': service,
                'operation': operation,
                'reason': reason,
                'actor_user_id': actor_user_id,
                'actor_username': actor_username,
                'source_org_ids': _org_ids(
                    source_org_ids if source_org_ids is not None else _request_org_ids(request)
                ),
                'target_org_id': int(target_org_id) if target_org_id is not None else None,
                'method': str(getattr(request, 'method', 'GET') or 'GET')[:12].upper(),
                'route': str(route)[:160],
                'correlation_id': _correlation_id(request),
            },
        }
        canonical = json.dumps(
            payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
        ).encode('utf-8')
        timestamp = int(time.time())
        sender_service = f'shizuha-{service}'
        body_hash = hashlib.sha256(canonical).hexdigest()
        signature = hmac.new(
            secret.encode('utf-8'),
            f'{sender_service}|{timestamp}|{body_hash}'.encode('utf-8'),
            hashlib.sha256,
        ).hexdigest()
        response = requests.post(
            getattr(
                settings,
                'SHIZUHA_CONNECT_SECURITY_EVENT_URL',
                'http://shizuha-connect.shizuha.svc.cluster.local:8019/api/internal/security-events/',
            ),
            json=payload,
            headers={
                'X-Internal-Service': sender_service,
                'X-Security-Event-Timestamp': str(timestamp),
                'X-Security-Event-Signature': signature,
            },
            timeout=float(getattr(settings, 'CONNECT_SECURITY_EVENT_TIMEOUT_SECONDS', 1.0)),
        )
        if response.status_code != 202:
            record_boundary_event_outcome('non_202')
            logger.error(
                'PLAT-4133 boundary event ingest rejected service=%s operation=%s status=%s',
                service, operation, response.status_code,
            )
            return False
        record_boundary_event_outcome('success')
        return True
    except requests.Timeout:
        record_boundary_event_outcome('timeout')
        logger.exception(
            'PLAT-4133 boundary event emit timed out service=%s operation=%s',
            service, operation,
        )
        return False
    except Exception:
        record_boundary_event_outcome('exception')
        logger.exception(
            'PLAT-4133 boundary event emit failed service=%s operation=%s',
            service, operation,
        )
        return False
