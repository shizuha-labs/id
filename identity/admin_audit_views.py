"""Read-only query surface for the admin-audit ledger (ID-37, HLD ID-5 §4.5).

Exposes staff/superuser endpoints that make the tamper-evident
``AdminAuditEvent`` chain (ID-34) queryable evidence rather than just logs:

* ``GET admin/audit/events/``          — filterable, paginated list.
* ``GET admin/audit/events/<seq>/``    — one event, redacted before/after +
                                         per-event hash-chain status.
* ``GET admin/audit/verify/``          — full-chain integrity verification
                                         (the API twin of the
                                         ``verify_admin_audit_chain`` command).

INV-5 (tamper evidence): responses never mutate the ledger; before/after
payloads are always passed through :func:`redact_audit_payload` so no
password/token/secret value can leak through the query surface.
"""
from __future__ import annotations

from django.db.models import Q
from django.utils.dateparse import parse_date, parse_datetime
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .admin_audit import (
    ACTION_ADMIN_POLICY_DENIED,
    derive_outcome,
    derive_service_slug,
    event_chain_status,
    redact_audit_payload,
    verify_chain,
)
from .models import AdminAuditEvent
from .permissions import IsStaffOrSuperUserAdmin

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

# Outcome filter value -> queryset predicate over the ledger.
_OUTCOME_FILTERS = {
    'denied': Q(action=ACTION_ADMIN_POLICY_DENIED) | Q(after__outcome='denied'),
    'failed': Q(after__outcome='failed'),
}
# Rows that are NOT allowed. Used via a subquery-exclude so that events with no
# ``outcome`` key are correctly treated as allowed — a direct JSON ``exclude``
# would drop them under Postgres NULL-negation semantics.
_NOT_ALLOWED = _OUTCOME_FILTERS['denied'] | _OUTCOME_FILTERS['failed']


def _serialize_summary(event) -> dict:
    """Compact row for list responses (no heavy before/after payloads)."""
    return {
        'seq': event.seq,
        'action': event.action,
        'outcome': derive_outcome(event),
        'actor': {
            'id': event.actor_id,
            'username': event.actor_username,
            'email': event.actor_email,
        },
        'target': {
            'type': event.target_type,
            'id': event.target_id,
            'repr': event.target_repr,
        },
        'service_slug': derive_service_slug(event),
        'created_at': event.created_at.isoformat(),
        'event_hash': event.event_hash,
    }


def _serialize_detail(event) -> dict:
    """Full row for detail responses: redacted diffs + hash-chain status."""
    data = _serialize_summary(event)
    data.update({
        'before': redact_audit_payload(event.before),
        'after': redact_audit_payload(event.after),
        'request_metadata': event.request_metadata,
        'prev_hash': event.prev_hash,
        'chain_status': event_chain_status(event),
    })
    return data


def _parse_when(raw):
    """Accept an ISO datetime or a bare ``YYYY-MM-DD`` date; else ``None``.

    A bare date returns a ``datetime.date`` (NOT ``parse_datetime``'s
    midnight coercion) so the caller can apply start/end-of-day semantics.
    """
    if not raw:
        return None
    if 'T' not in raw and ' ' not in raw and ':' not in raw:
        return parse_date(raw)
    return parse_datetime(raw)


def _when_boundary(value, *, end_of_day: bool):
    """Resolve a parsed ``from``/``to`` value to a tz-aware filter boundary.

    A bare ``YYYY-MM-DD`` date means the start (``from``) or end (``to``) of
    that day in the configured timezone — NOT midnight. Midnight silently
    excludes every event created later in the local day (the ID-37
    time-of-day bug: ``to=tomorrow`` filtered out events created after
    00:00 IST = 18:30 UTC the prior day). Naive ISO datetimes are
    interpreted in the configured timezone for the same reason.
    """
    from datetime import datetime, time as dtime
    from django.utils import timezone as tz

    if isinstance(value, datetime):
        if tz.is_naive(value):
            return tz.make_aware(value, tz.get_current_timezone())
        return value
    return tz.make_aware(
        datetime.combine(value, dtime.max if end_of_day else dtime.min),
        tz.get_current_timezone(),
    )


@extend_schema(tags=['Admin Audit'])
class AdminAuditEventListView(APIView):
    """List/filter the admin-audit ledger (staff or superuser).

    Query params (all optional, AND-combined):
      ``action``         exact action string (e.g. ``user_services.grant``)
      ``actor_id``       actor user id
      ``actor_username`` actor username (exact)
      ``target_user_id`` events whose target is this user
      ``service_slug``   catalog/grant/revoke/request events for this slug
      ``outcome``        ``allowed`` | ``denied`` | ``failed``
      ``from`` / ``to``  created_at range (ISO datetime or ``YYYY-MM-DD``)
      ``limit`` / ``offset`` pagination (limit default 50, max 200)
    """
    permission_classes = [IsStaffOrSuperUserAdmin]

    def get(self, request):
        qs = AdminAuditEvent.objects.all()
        params = request.query_params

        action = params.get('action')
        if action:
            qs = qs.filter(action=action)

        actor_id = params.get('actor_id')
        if actor_id:
            try:
                qs = qs.filter(actor_id=int(actor_id))
            except (TypeError, ValueError):
                return Response({'error': 'actor_id must be an integer'},
                                status=status.HTTP_400_BAD_REQUEST)

        actor_username = params.get('actor_username')
        if actor_username:
            qs = qs.filter(actor_username=actor_username)

        target_user_id = params.get('target_user_id')
        if target_user_id:
            qs = qs.filter(target_type='user', target_id=str(target_user_id))

        service_slug = params.get('service_slug')
        if service_slug:
            qs = qs.filter(
                Q(target_type='tool', target_id=service_slug)
                | Q(target_type='service_access_request',
                    target_repr__endswith=f':{service_slug}')
                | Q(after__requested_slugs__contains=[service_slug])
            )

        outcome = params.get('outcome')
        if outcome:
            if outcome == 'allowed':
                qs = qs.exclude(
                    pk__in=AdminAuditEvent.objects.filter(_NOT_ALLOWED).values('pk'))
            elif outcome in _OUTCOME_FILTERS:
                qs = qs.filter(_OUTCOME_FILTERS[outcome])
            else:
                return Response(
                    {'error': 'outcome must be allowed, denied, or failed'},
                    status=status.HTTP_400_BAD_REQUEST)

        raw_from, raw_to = params.get('from'), params.get('to')
        when_from = _parse_when(raw_from)
        if raw_from and when_from is None:
            return Response({'error': 'from is not a valid date/datetime'},
                            status=status.HTTP_400_BAD_REQUEST)
        if when_from:
            qs = qs.filter(created_at__gte=_when_boundary(when_from, end_of_day=False))
        when_to = _parse_when(raw_to)
        if raw_to and when_to is None:
            return Response({'error': 'to is not a valid date/datetime'},
                            status=status.HTTP_400_BAD_REQUEST)
        if when_to:
            qs = qs.filter(created_at__lte=_when_boundary(when_to, end_of_day=True))

        try:
            limit = int(params.get('limit', DEFAULT_PAGE_SIZE))
            offset = int(params.get('offset', 0))
        except (TypeError, ValueError):
            return Response({'error': 'limit and offset must be integers'},
                            status=status.HTTP_400_BAD_REQUEST)
        limit = max(1, min(limit, MAX_PAGE_SIZE))
        offset = max(0, offset)

        total = qs.count()
        # Newest-first is the operator's default reading order; seq is a total
        # order so this is stable and index-backed.
        page = qs.order_by('-seq')[offset:offset + limit]
        return Response({
            'count': total,
            'limit': limit,
            'offset': offset,
            'results': [_serialize_summary(e) for e in page],
        })


@extend_schema(tags=['Admin Audit'])
class AdminAuditEventDetailView(APIView):
    """Fetch one audit event by ``seq`` with redacted diffs + chain status."""
    permission_classes = [IsStaffOrSuperUserAdmin]

    def get(self, request, seq):
        try:
            event = AdminAuditEvent.objects.get(seq=seq)
        except AdminAuditEvent.DoesNotExist:
            return Response({'error': 'Audit event not found'},
                            status=status.HTTP_404_NOT_FOUND)
        return Response(_serialize_detail(event))


@extend_schema(tags=['Admin Audit'])
class AdminAuditVerifyView(APIView):
    """Verify the full hash chain and report the first broken event, if any."""
    permission_classes = [IsStaffOrSuperUserAdmin]

    def get(self, request):
        from django.utils import timezone

        result = verify_chain()
        return Response({
            'ok': result.ok,
            'checked': result.checked,
            'first_bad_seq': result.first_bad_seq,
            'reason': result.reason,
            'verified_at': timezone.now().isoformat(),
        })
