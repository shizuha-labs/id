"""
Thin audit-emission adapter for shizuha-id security signals.

This is intentionally a *thin* indirection layer. The final transport/sink for
platform audit signals is owned by PLAT-47 (Ryo). Until that sink shape is
locked, ``emit_refresh_storm`` writes a single structured log record on the
``identity.audit`` logger so the signal is observable end-to-end; swapping in
PLAT-47's sink is a one-function change here with no call-site churn.

Signal contract (ADR-PLAT-002 §5-INV-2 / §6 audit-signal table):
  event_type               = "refresh_storm"
  count                    = refresh events observed in the trailing window
  threshold                = configured T
  window_s                 = configured W
  upstream_attribution_summary
                           = degenerate {"shizuha-id": count} sentinel.
                             shizuha-id emits the storm signal ONLY; it does
                             NOT emit per-upstream refresh-grant events (those
                             come from the sidecar, PLAT-43 / §5-INV-2a).
"""
from __future__ import annotations

import logging

from django.utils import timezone

from .refresh_storm import StormDecision

logger = logging.getLogger("identity.audit")

EVENT_TYPE = "refresh_storm"


def emit_refresh_storm(decision: StormDecision) -> None:
    """Emit the population-wide refresh-storm audit signal.

    NOTE: transport is a structured log today; reconcile with PLAT-47's audit
    sink once its interface is finalized (single point of change).
    """
    payload = {
        "event_type": EVENT_TYPE,
        "count": decision.count,
        "threshold": decision.threshold,
        "window_s": decision.window_s,
        "upstream_attribution_summary": decision.attribution_summary,
    }
    logger.warning(
        "refresh_storm detected: %s refreshes in %ss (threshold %s)",
        decision.count,
        decision.window_s,
        decision.threshold,
        extra={"audit_signal": payload},
    )


# ---------------------------------------------------------------------------
# Step-up audit signals (HIVE-6 / HLD §4.1 notify+audit, §7 lock).
#
# Same thin structured-log indirection as the refresh-storm signal; reconcile
# with PLAT-47's audit sink when it lands (single point of change here).
# ---------------------------------------------------------------------------
def emit_step_up_event(event_type: str, *, owner_id, action: str = '',
                       resource_id: str = '', outcome: str = '', detail: str = '') -> None:
    """Emit a step-up / enrollment audit signal.

    ``event_type`` is one of ``step_up_challenge`` | ``step_up_answer`` |
    ``step_up_verify`` | ``step_up_enroll`` | ``step_up_reenroll`` |
    ``step_up_recover`` | ``step_up_lock``. Every §4.1 enrollment-lifecycle
    event emits one of these AND a separate owner notification (the detectability
    backstop) — the notification is fired by the view, this records the audit leg.
    """
    payload = {
        'event_type': event_type,
        'owner_id': owner_id,
        'action': action,
        'resource_id': resource_id,
        'outcome': outcome,
        'detail': detail,
    }
    logger.info(
        'step_up event %s owner=%s action=%s outcome=%s',
        event_type, owner_id, action, outcome,
        extra={'audit_signal': payload},
    )

# ---------------------------------------------------------------------------
# OAuth client revocation audit signal (PLAT-47).
# ---------------------------------------------------------------------------
def emit_oauth_client_revocation(*, revoked_client_id: str, revoked_agent_id: str | None,
                                 revoker_identity: str, reason: str,
                                 revoked_tokens: int, revoked_at: str) -> None:
    """Emit a queryable structured audit signal for client-id revocation.

    Contract required by PLAT-47:
      (ts, revoked_client_id, revoked_agent_id_or_null, revoker_identity, reason)
    plus ``revoked_tokens`` for operator observability.
    """
    payload = {
        'event_type': 'oauth_client_revocation',
        'ts': revoked_at,
        'revoked_client_id': revoked_client_id,
        'revoked_agent_id_or_null': revoked_agent_id or None,
        'revoker_identity': revoker_identity,
        'reason': reason,
        'revoked_tokens': revoked_tokens,
    }
    logger.warning(
        'oauth client revoked client_id=%s agent_id=%s revoked_tokens=%s revoker=%s',
        revoked_client_id,
        revoked_agent_id or '-',
        revoked_tokens,
        revoker_identity,
        extra={'audit_signal': payload},
    )


# ---------------------------------------------------------------------------
# Agent token-mint attestation audit signals (PLAT-49).
# ---------------------------------------------------------------------------
def emit_mint_attestation_rejection(*, reason: str, presented_agent_id: str,
                                    resolved_namespace: str = '', pod_name: str = '',
                                    correlation_id: str = '') -> None:
    """Emit append-only structured audit for rejected agent token mints."""
    payload = {
        'event_type': 'mint-rejected',
        'reason': reason,
        'failure_class': reason,
        'presented_agent_id': presented_agent_id,
        'claimed_agent_id': presented_agent_id,
        'resolved_namespace': resolved_namespace,
        'verified_namespace': resolved_namespace,
        'pod_name': pod_name,
        'verified_pod_name': pod_name,
        'correlation_id': correlation_id,
        'timestamp': timezone.now().isoformat(),
    }
    logger.warning(
        'agent token mint rejected reason=%s agent_id=%s namespace=%s pod=%s correlation_id=%s',
        reason, presented_agent_id, resolved_namespace, pod_name, correlation_id,
        extra={'audit_signal': payload},
    )

def emit_agent_claim_event(*, agent_user_id, agent_username, actor_user_id, actor_email='', outcome='claimed', previous_owner_id=None) -> None:
    """Emit structured audit for Hive external-agent ownership claims (HIVE-199)."""
    payload = {
        'event_type': 'agent_ownership_claim',
        'agent_user_id': agent_user_id,
        'agent_username': agent_username,
        'actor_user_id': actor_user_id,
        'actor_email': actor_email,
        'outcome': outcome,
        'previous_owner_id': previous_owner_id,
        'at': timezone.now().isoformat(),
    }
    logger.warning(
        'agent ownership claim: agent=%s actor=%s outcome=%s previous_owner=%s',
        agent_username,
        actor_user_id,
        outcome,
        previous_owner_id,
        extra={'audit_signal': payload},
    )

# ---------------------------------------------------------------------------
# Profile/self-service identity mutation audit signals (ID-47).
# ---------------------------------------------------------------------------
def emit_profile_update_event(*, actor, target_user, surface: str, changed_fields, before=None, after=None) -> None:
    """Emit structured audit for self-service profile/directory updates.

    This is a lightweight structured-log trail (not the privileged admin hash
    chain) for directory-impacting owner edits. It records the acting user,
    target user, update surface, and changed field names; before/after values
    are sanitized by the caller and limited to profile/directory identifiers.
    """
    changed_fields = sorted(set(changed_fields or []))
    payload = {
        'event_type': 'profile_update',
        'actor_id': getattr(actor, 'id', None),
        'actor_username': getattr(actor, 'username', '') or '',
        'target_user_id': getattr(target_user, 'id', None),
        'target_username': getattr(target_user, 'username', '') or '',
        'surface': surface,
        'changed_fields': changed_fields,
        'before': before or {},
        'after': after or {},
        'at': timezone.now().isoformat(),
    }
    logger.info(
        'profile update surface=%s actor=%s target=%s fields=%s',
        surface,
        payload['actor_id'],
        payload['target_user_id'],
        ','.join(changed_fields),
        extra={'audit_signal': payload},
    )

# ---------------------------------------------------------------------------
# Dedicated QA e2e principal-class session-mint audit signal (ID-85/ID-86;
# ren's PLAT-1247 sign-off answer A1, C1-scoped).
# ---------------------------------------------------------------------------
def emit_qa_e2e_session_mint(*, principal: str, actor: str, mint_path: str,
                             session_id: str, ts: str) -> None:
    """Emit one typed ``qa_e2e_session_mint`` audit signal.

    Fires ONLY for principals in the dedicated QA e2e class (the
    ``QA_E2E_PRINCIPALS`` allowlist — the C1 class check). The watchdog-facing
    contract is (principal, actor, mint_path, session_id, timestamp): filterable
    for mint-rate spikes, entitlement-change pings (A2 lives on the admin
    surface), and session usage outside the scoped E2E surfaces. Same thin
    structured-log indirection as the other signals here; PLAT-47's sink is a
    single-point-of-change swap.
    """
    payload = {
        'event_type': 'qa_e2e_session_mint',
        'principal': principal,
        'actor': actor,
        'mint_path': mint_path,
        'session_id': session_id or None,
        'timestamp': ts,
    }
    logger.warning(
        'qa_e2e_session_mint principal=%s actor=%s mint_path=%s session_id=%s',
        payload['principal'], payload['actor'], payload['mint_path'],
        payload['session_id'] or '-',
        extra={'audit_signal': payload},
    )
