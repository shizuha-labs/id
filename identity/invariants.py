"""PLAT-1278: Shizuha ID invariant metrics for Prometheus (PLAT-1255 pattern).

Read-only self-checks exposing invariant drift so the existing
Alertmanager/critical-alert-notifier path can DM the on-call lead. They must
not file Pulse tasks or mutate identity state.

Invariants asserted here:
- id_users_invalid_lifecycle{check="approved_missing_timestamp"}: every
  'approved' profile carries the approval timestamp the audited decision path
  always writes (admin_audit.decide_approval). A violation means the profile
  was flipped outside the audited path.
- id_users_invalid_lifecycle{check="active_not_approved"}: every active user
  account has an 'approved' profile — the LoginView/approval flow guarantees
  is_active only flips on approval (ID-31 fail-safe).
- id_service_grants_disabled_total: no user grant (UserProfile.enabled_tools)
  references a disabled Tool. get_effective_services() filters these at read
  time (INV-5/ID-11), so rows here are silent drift that would resurface if
  the tool is ever re-enabled unreviewed.
- id_token_event_total{stage,outcome}: token mint/refresh outcomes counted on
  the write path (login password/2FA, refresh, service-token) so Prometheus
  can alert on failure-rate spikes. Counters live in Redis so every gunicorn
  worker shares one series.
- id_membership_projection_total{outcome}: bounded outcomes for the Admin→ID
  organization-membership projection.  Any unavailable/invalid projection is
  observable without logging a JWT or membership payload (PLAT-5104).
- id_lifecycle_revocation_total{outcome}: ID-41 lifecycle-driven token
  revocations (deactivate/soft-delete advancing the access cutoff via
  transition_user). An ``outcome="failure"`` increase means a removed user's
  live tokens may not have been killed — Prometheus alerts the on-call lead.
- id_users_invalid_lifecycle{check="deactivated_without_revocation"}: ID-41
  invariant — every 'deactivated'/'deleted' profile carries a non-null
  ``access_revoked_before`` (its live sessions were revoked at removal). A
  violation is a removed user whose pre-removal tokens/sessions can still
  validate: the exact gap ID-41 closes.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import redis
from django.conf import settings

TOKEN_STAGES = ('password', 'twofa', 'refresh', 'service_token')
TOKEN_OUTCOMES = ('success', 'failure')
_COUNTER_KEY = 'id:metrics:token_event:{stage}:{outcome}'

MEMBERSHIP_PROJECTION_OUTCOMES = (
    'success',
    'authoritative_empty',
    'timeout',
    'non_200',
    'invalid_payload',
    'request_error',
    # PLAT-5343 slice 1: the v2 path is selected but the assertion material
    # (signing key / service credential) is missing — a real failure class
    # with its own vocabulary entry, per the note below.
    'v2_emission_unavailable',
    'exception',
)
_MEMBERSHIP_PROJECTION_KEY = 'id:metrics:membership_projection:{outcome}'

# ID-41: lifecycle-driven revocation outcomes. States that must carry a
# revocation cutoff are duplicated as literals here (not imported from
# lifecycle) to keep this metrics module read-only and dependency-free.
LIFECYCLE_REVOCATION_OUTCOMES = ('success', 'failure')
_LIFECYCLE_REVOCATION_KEY = 'id:metrics:lifecycle_revocation:{outcome}'
_REVOCATION_REQUIRED_STATES = ('deactivated', 'deleted')


@dataclass(frozen=True)
class IdInvariantMetrics:
    approved_missing_timestamp: int
    active_not_approved: int
    grants_disabled: int
    token_events: dict = field(default_factory=dict)
    membership_projection_events: dict = field(default_factory=dict)
    deactivated_without_revocation: int = 0
    lifecycle_revocations: dict = field(default_factory=dict)
    probe_errors: int = 0


def _redis_client(redis_client=None):
    if redis_client is not None:
        return redis_client
    url = getattr(settings, 'REFRESH_STORM_REDIS_URL', None) or getattr(
        settings, 'CELERY_BROKER_URL', 'redis://localhost:6379/2'
    )
    return redis.Redis.from_url(url, decode_responses=True)


def record_token_event(stage: str, outcome: str, redis_client=None) -> None:
    """Write-path hook: count a token mint/refresh outcome.

    Fail-open by design — the metrics path must never break authentication.
    """
    try:
        _redis_client(redis_client).incr(_COUNTER_KEY.format(stage=stage, outcome=outcome))
    except Exception:  # pragma: no cover - defensive; never break the auth path
        pass


def record_membership_projection_event(outcome: str, redis_client=None) -> None:
    """Count one bounded Admin→ID membership-projection outcome.

    The projection result itself is deliberately never accepted here, keeping
    the metric label space bounded and preventing membership data from reaching
    Redis keys or Prometheus labels.  Fail-open: observability must never change
    token-mint semantics.

    ⚠️ `'exception'` is NOT recorded by any caller and is not meant to be. It is
    the sink for the out-of-vocabulary coercion below, so `exception > 0` means
    exactly one thing: **somebody passed a label string that is not in
    `MEMBERSHIP_PROJECTION_OUTCOMES`** — a typo surfaces as a visible series
    instead of vanishing.

    This is a deliberate divergence from the admin service's model, which
    *rejects* an unknown outcome (`return False`, no increment). Both are
    defensible; this one is chosen so a mislabelled call is discoverable rather
    than silent. **Do not repurpose it to record a real exception** — the moment
    a caller passes `'exception'` for a genuine error, the label stops
    distinguishing "bad label" from "bad request" and the diagnostic is lost.
    A real exception outcome needs its own vocabulary entry (PLAT-5334 P3,
    @reika).
    """
    if outcome not in MEMBERSHIP_PROJECTION_OUTCOMES:
        outcome = 'exception'
    try:
        _redis_client(redis_client).incr(
            _MEMBERSHIP_PROJECTION_KEY.format(outcome=outcome)
        )
    except Exception:  # pragma: no cover - defensive; exposed by probe_errors
        pass


def record_lifecycle_revocation(outcome: str, redis_client=None) -> None:
    """Write-path hook (ID-41): count a lifecycle-driven token revocation.

    Called from ``lifecycle.transition_user`` when a deactivate/soft-delete
    advances the user's access-revocation cutoff. ``failure`` is incremented in
    the except branch *before* the aborting exception re-raises, so the counter
    survives the transaction rollback (the Redis write is non-transactional) and
    Prometheus can alert the on-call lead on any revocation failure. Fail-open —
    the metric must never break the (already fail-closed) revocation path.
    """
    if outcome not in LIFECYCLE_REVOCATION_OUTCOMES:
        return
    try:
        _redis_client(redis_client).incr(_LIFECYCLE_REVOCATION_KEY.format(outcome=outcome))
    except Exception:  # pragma: no cover - defensive; never break the transition path
        pass


def _lifecycle_revocation_counts(redis_client) -> dict:
    keys = [_LIFECYCLE_REVOCATION_KEY.format(outcome=o) for o in LIFECYCLE_REVOCATION_OUTCOMES]
    values = redis_client.mget(keys)
    return {
        outcome: (int(raw) if raw else 0)
        for outcome, raw in zip(LIFECYCLE_REVOCATION_OUTCOMES, values)
    }


def _token_event_counts(redis_client) -> dict:
    counts = {}
    keys = [
        _COUNTER_KEY.format(stage=stage, outcome=outcome)
        for stage in TOKEN_STAGES
        for outcome in TOKEN_OUTCOMES
    ]
    values = redis_client.mget(keys)
    i = 0
    for stage in TOKEN_STAGES:
        for outcome in TOKEN_OUTCOMES:
            raw = values[i]
            counts[(stage, outcome)] = int(raw) if raw else 0
            i += 1
    return counts


def _membership_projection_counts(redis_client) -> dict:
    keys = [
        _MEMBERSHIP_PROJECTION_KEY.format(outcome=outcome)
        for outcome in MEMBERSHIP_PROJECTION_OUTCOMES
    ]
    values = redis_client.mget(keys)
    return {
        outcome: int(raw) if raw else 0
        for outcome, raw in zip(MEMBERSHIP_PROJECTION_OUTCOMES, values)
    }


def collect_id_invariant_metrics(redis_client=None) -> IdInvariantMetrics:
    """Collect the PLAT-1278 Shizuha ID self-check metrics (read-only)."""
    from django.contrib.auth import get_user_model

    from .models import Tool, UserProfile

    User = get_user_model()
    probe_errors = 0

    approved_missing_timestamp = UserProfile.objects.filter(
        approval_status='approved', approved_at__isnull=True
    ).count()

    active_not_approved = (
        User.objects.filter(is_active=True)
        .exclude(profile__approval_status='approved')
        .count()
    )

    grants_disabled = UserProfile.enabled_tools.through.objects.filter(
        tool__in=Tool.objects.filter(is_active=False)
    ).count()

    # ID-41: a removed (deactivated/deleted) user must carry a revocation
    # cutoff; a null cutoff on such a profile is a live-session leak.
    deactivated_without_revocation = UserProfile.objects.filter(
        lifecycle_state__in=_REVOCATION_REQUIRED_STATES,
        access_revoked_before__isnull=True,
    ).count()

    token_events = {}
    membership_projection_events = {}
    lifecycle_revocations = {}
    try:
        client = _redis_client(redis_client)
        token_events = _token_event_counts(client)
        membership_projection_events = _membership_projection_counts(client)
        lifecycle_revocations = _lifecycle_revocation_counts(client)
    except Exception:
        # Redis being unreachable must not hide the DB-backed gauges; the
        # probe-error gauge (alerted on) records that the counter half failed.
        probe_errors = 1

    return IdInvariantMetrics(
        approved_missing_timestamp=approved_missing_timestamp,
        active_not_approved=active_not_approved,
        grants_disabled=grants_disabled,
        token_events=token_events,
        membership_projection_events=membership_projection_events,
        deactivated_without_revocation=deactivated_without_revocation,
        lifecycle_revocations=lifecycle_revocations,
        probe_errors=probe_errors,
    )


def render_prometheus_metrics(metrics: IdInvariantMetrics) -> str:
    """Render Prometheus text exposition without adding a runtime dependency."""
    lines = [
        '# HELP id_users_invalid_lifecycle Users whose lifecycle flags violate the ID-31 approval invariants.',
        '# TYPE id_users_invalid_lifecycle gauge',
        f'id_users_invalid_lifecycle{{check="approved_missing_timestamp"}} {metrics.approved_missing_timestamp}',
        f'id_users_invalid_lifecycle{{check="active_not_approved"}} {metrics.active_not_approved}',
        f'id_users_invalid_lifecycle{{check="deactivated_without_revocation"}} {metrics.deactivated_without_revocation}',
        '# HELP id_service_grants_disabled_total User service grants referencing a disabled Tool.',
        '# TYPE id_service_grants_disabled_total gauge',
        f'id_service_grants_disabled_total {metrics.grants_disabled}',
        '# HELP id_token_event_total Token mint/refresh outcomes counted on the write path (Redis-backed).',
        '# TYPE id_token_event_total counter',
    ]
    for (stage, outcome), value in sorted(metrics.token_events.items()):
        lines.append(f'id_token_event_total{{stage="{stage}",outcome="{outcome}"}} {value}')
    lines += [
        '# HELP id_membership_projection_total Admin-to-ID organization-membership projection outcomes.',
        '# TYPE id_membership_projection_total counter',
    ]
    for outcome in MEMBERSHIP_PROJECTION_OUTCOMES:
        value = metrics.membership_projection_events.get(outcome, 0)
        lines.append(f'id_membership_projection_total{{outcome="{outcome}"}} {value}')
    lines += [
        '# HELP id_lifecycle_revocation_total ID-41 lifecycle-driven token revocations (deactivate/soft-delete).',
        '# TYPE id_lifecycle_revocation_total counter',
    ]
    for outcome in LIFECYCLE_REVOCATION_OUTCOMES:
        value = metrics.lifecycle_revocations.get(outcome, 0)
        lines.append(f'id_lifecycle_revocation_total{{outcome="{outcome}"}} {value}')
    lines += [
        '# HELP id_invariant_probe_errors Invariant collection halves that failed this scrape (fail-loud).',
        '# TYPE id_invariant_probe_errors gauge',
        f'id_invariant_probe_errors {metrics.probe_errors}',
    ]
    return '\n'.join(lines) + '\n'
