"""
Service-layer wrappers for privileged Shizuha ID admin mutations (ID-34).

HLD ID-5 (`ed927f38-63a1-442d-a378-c59fb9a8c023`): every privileged admin
mutation must land in the append-only ``AdminAuditEvent`` hash chain. These
wrappers are the ONLY sanctioned write path — each one performs the mutation
and appends its audit event inside a single ``transaction.atomic`` block, so
a failed audit write rolls the mutation back (no silent unaudited mutation)
and a failed mutation leaves no orphan audit row.

Views must call these instead of mutating directly. Non-transactional side
effects (notification emails, token revocation fan-out) stay in the caller,
AFTER the wrapper commits.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

from .models import (
    ADMIN_AUDIT_GENESIS_HASH,
    AdminAuditEvent,
    UserProfile,
)
from .services import get_default_new_user_tools

logger = logging.getLogger('identity.audit')

User = get_user_model()

# Action vocabulary — keep stable; consumers query on these strings.
ACTION_SERVICE_CATALOG_UPDATE = 'service_catalog.update'
ACTION_USER_SERVICES_GRANT = 'user_services.grant'
ACTION_USER_SERVICES_REVOKE = 'user_services.revoke'
ACTION_ACCESS_REQUEST_REVIEW = 'access_request.review'
ACTION_USER_ACCOUNT_REVIEW = 'user_account.review'
ACTION_ADMIN_SET_PASSWORD = 'user_password.admin_set'
ACTION_ADMIN_USER_CREATE = 'user_account.admin_create'
ACTION_ADMIN_USER_UPDATE = 'user_account.admin_update'
ACTION_ADMIN_USER_DELETE = 'user_account.admin_delete'
ACTION_DJANGO_ADMIN_MUTATION = 'django_admin.mutation'
ACTION_ADMIN_POLICY_DENIED = 'admin_policy.denied'


def audited_admin_policy_denied(*, actor, target_type, target_id, target_repr='',
                                reason_code, attempted_action, attempted=None,
                                request=None):
    """Append a denied privileged-admin attempt without mutating the target.

    Denied attempts are security-relevant and must be visible in the same
    tamper-evident ledger as successful admin mutations. ``attempted`` must be
    a sanitized shape only (field names/slugs/booleans), never secrets.
    """
    return AdminAuditEvent.objects.append(
        action=ACTION_ADMIN_POLICY_DENIED,
        actor=actor,
        target_type=target_type,
        target_id=target_id,
        target_repr=target_repr,
        before={},
        after={
            'outcome': 'denied',
            'reason_code': reason_code,
            'attempted_action': attempted_action,
            'attempted': attempted or {},
        },
        request_metadata=request_metadata(request),
    )


def request_metadata(request) -> dict:
    """Extract correlation/request metadata for the audit row.

    Never raises: audit emission must not fail because a header is odd, and
    it must never capture bodies (password material) — metadata only.
    """
    if request is None:
        return {}
    try:
        meta = getattr(request, 'META', {}) or {}
        headers = getattr(request, 'headers', {}) or {}
        return {
            'method': getattr(request, 'method', '') or '',
            'path': getattr(request, 'path', '') or '',
            'remote_addr': meta.get('REMOTE_ADDR', ''),
            'correlation_id': headers.get('X-Correlation-ID', '')
            or headers.get('X-Request-ID', ''),
            'user_agent': (headers.get('User-Agent', '') or '')[:254],
        }
    except Exception:  # pragma: no cover — defensive
        return {}


# ---------------------------------------------------------------------------
# Wrappers — one per privileged mutation class.
# ---------------------------------------------------------------------------
def audited_service_catalog_update(*, actor, tool, changes, request=None):
    """Apply validated config ``changes`` to a Tool row, audited."""
    fields = list(changes)
    before = {f: getattr(tool, f) for f in fields}
    with transaction.atomic():
        for field, value in changes.items():
            setattr(tool, field, value)
        tool.save(update_fields=fields + ['updated_at'])
        AdminAuditEvent.objects.append(
            action=ACTION_SERVICE_CATALOG_UPDATE,
            actor=actor,
            target_type='tool',
            target_id=tool.slug,
            target_repr=tool.display_name,
            before=before,
            after=dict(changes),
            request_metadata=request_metadata(request),
        )
    return tool


def audited_user_services_change(*, actor, user, tools, action, request=None,
                                 break_glass_reason=''):
    """Grant or revoke a set of tools on a user's profile, audited.

    ``action`` is ``'grant'`` or ``'revoke'``. Returns the resulting enabled
    slug list (the same value the admin endpoint reports back).
    """
    if action not in ('grant', 'revoke'):
        raise ValueError(f'unknown user-services action: {action!r}')
    with transaction.atomic():
        profile, _ = UserProfile.objects.get_or_create(user=user)
        before = sorted(profile.enabled_tools.values_list('slug', flat=True))
        if action == 'grant':
            profile.enabled_tools.add(*tools)
        else:
            profile.enabled_tools.remove(*tools)
        after = sorted(profile.enabled_tools.values_list('slug', flat=True))
        AdminAuditEvent.objects.append(
            action=ACTION_USER_SERVICES_GRANT if action == 'grant' else ACTION_USER_SERVICES_REVOKE,
            actor=actor,
            target_type='user',
            target_id=user.id,
            target_repr=user.username,
            before={'enabled_services': before},
            after={'enabled_services': after,
                   'requested_slugs': sorted(t.slug for t in tools),
                   **({'break_glass': True, 'break_glass_reason': break_glass_reason}
                      if break_glass_reason else {})},
            request_metadata=request_metadata(request),
        )
    return after


def audited_access_request_review(*, actor, access_request, new_status,
                                  review_note='', request=None, break_glass_reason=''):
    """Approve/deny a ServiceAccessRequest (+ auto-grant on approval), audited."""
    before = {
        'status': access_request.status,
        'review_note': access_request.review_note,
    }
    with transaction.atomic():
        access_request.status = new_status
        access_request.review_note = review_note
        access_request.reviewed_by_id = getattr(actor, 'id', None)
        access_request.reviewed_at = timezone.now()
        access_request.save()

        granted = False
        if new_status == 'approved':
            profile, _ = UserProfile.objects.get_or_create(user=access_request.user)
            profile.enabled_tools.add(access_request.tool)
            granted = True

        AdminAuditEvent.objects.append(
            action=ACTION_ACCESS_REQUEST_REVIEW,
            actor=actor,
            target_type='service_access_request',
            target_id=access_request.id,
            target_repr=f'{access_request.user.username}:{access_request.tool.slug}',
            before=before,
            after={
                'status': new_status,
                'review_note': review_note,
                'tool_granted': granted,
                **({'break_glass': True, 'break_glass_reason': break_glass_reason}
                   if break_glass_reason else {}),
            },
            request_metadata=request_metadata(request),
        )
    return access_request


def audited_user_approval(*, actor, user, profile, new_status,
                          review_note='', request=None):
    """Approve/deny a pending account, audited.

    Owns every DB write of the review (lifecycle transition, profile review
    fields, ``is_active``, and least-privilege default grant on approval).
    Notification emails stay in the view, after commit.
    """
    from .lifecycle import LifecycleState, transition_user

    before = {
        'approval_status': profile.approval_status,
        'lifecycle_state': profile.lifecycle_state,
        'is_active': user.is_active,
    }
    target_state = LifecycleState.ACTIVE if new_status == 'approved' else LifecycleState.DENIED
    with transaction.atomic():
        profile = transition_user(
            user, target_state, actor=actor, reason=review_note,
        )
        profile.approval_note = review_note
        profile.approved_by_id = getattr(actor, 'id', None)
        profile.approved_at = timezone.now()
        profile.save(update_fields=['approval_note', 'approved_by_id', 'approved_at'])

        default_slugs = []
        if new_status == 'approved':
            default_tools = get_default_new_user_tools()
            profile.enabled_tools.set(default_tools)
            default_slugs = sorted(t.slug for t in default_tools)

        user.refresh_from_db(fields=['is_active'])
        AdminAuditEvent.objects.append(
            action=ACTION_USER_ACCOUNT_REVIEW,
            actor=actor,
            target_type='user',
            target_id=user.id,
            target_repr=user.username,
            before=before,
            after={
                'approval_status': profile.approval_status,
                'lifecycle_state': profile.lifecycle_state,
                'is_active': user.is_active,
                'review_note': review_note,
                'default_services_granted': default_slugs,
            },
            request_metadata=request_metadata(request),
        )
    return profile


def audited_admin_set_password(*, actor, user, new_password, request=None,
                               break_glass_reason=''):
    """Set a user's password from the superuser admin path, audited.

    The audit row records THAT the password changed — never any password
    material. Session revocation (ID-7) is a post-commit side effect owned
    by the caller.
    """
    with transaction.atomic():
        user.set_password(new_password)
        user.save(update_fields=['password'])
        AdminAuditEvent.objects.append(
            action=ACTION_ADMIN_SET_PASSWORD,
            actor=actor,
            target_type='user',
            target_id=user.id,
            target_repr=user.username,
            before={},
            after={'password_changed': True, **({'break_glass': True, 'break_glass_reason': break_glass_reason} if break_glass_reason else {})},
            request_metadata=request_metadata(request),
        )
    return user


def audited_admin_user_create(*, actor, username, email, password,
                              first_name='', last_name='', is_staff=False,
                              is_superuser=False, is_active=True, request=None):
    """Create a user from the superuser admin path, audited.

    Owns every DB write of the create (account, privilege flags, the
    trusted 'approved' profile status). The audit row records the resulting
    account shape — never any password material.
    """
    with transaction.atomic():
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
        )
        user.is_staff = is_staff
        user.is_superuser = is_superuser
        user.is_active = is_active
        user.save()

        # Admin-created accounts are trusted — mark approved explicitly (ID-31)
        # and active in the lifecycle FSM (ID-32). Create is not a transition
        # from a prior persisted state, so no UserLifecycleAudit row is emitted.
        profile, _ = UserProfile.objects.get_or_create(user=user)
        profile.approval_status = 'approved'
        profile.lifecycle_state = 'active'
        profile.deactivated_at = None
        profile.deleted_at = None
        profile.save(update_fields=[
            'approval_status', 'lifecycle_state', 'deactivated_at', 'deleted_at',
        ])

        AdminAuditEvent.objects.append(
            action=ACTION_ADMIN_USER_CREATE,
            actor=actor,
            target_type='user',
            target_id=user.id,
            target_repr=user.username,
            before={},
            after={
                'username': username,
                'email': email,
                'is_staff': bool(is_staff),
                'is_superuser': bool(is_superuser),
                'is_active': bool(is_active),
                'approval_status': 'approved',
                'lifecycle_state': 'active',
            },
            request_metadata=request_metadata(request),
        )
    return user


def audited_admin_user_update(*, actor, user, changes, new_password=None,
                              request=None, break_glass_reason=''):
    """Apply validated field ``changes`` (and optional password) to a user
    from the superuser admin path, audited.

    ``changes`` maps User field name -> new value (username/email/names/
    privilege flags). The audit row records field-level before/after plus a
    ``password_changed`` flag — never any password material.
    """
    fields = list(changes)
    before = {f: getattr(user, f) for f in fields}
    after = dict(changes)
    with transaction.atomic():
        for field, value in changes.items():
            setattr(user, field, value)
        if new_password is not None:
            user.set_password(new_password)
            after['password_changed'] = True
        if break_glass_reason:
            after['break_glass'] = True
            after['break_glass_reason'] = break_glass_reason
        user.save()
        AdminAuditEvent.objects.append(
            action=ACTION_ADMIN_USER_UPDATE,
            actor=actor,
            target_type='user',
            target_id=user.id,
            target_repr=user.username,
            before=before,
            after=after,
            request_metadata=request_metadata(request),
        )
    return user


def audited_admin_user_delete(*, actor, user, request=None, break_glass_reason=''):
    """Soft-delete a user from the superuser admin path, audited.

    ID-32 replaces the previous hard delete with a lifecycle tombstone so the
    user row and audit trail survive. The admin audit ledger records the
    privileged delete request atomically with the lifecycle mutation.
    """
    from .lifecycle import (
        LEGAL_TRANSITIONS,
        IllegalLifecycleTransition,
        LifecycleState,
        derive_lifecycle_state,
        transition_user,
    )

    profile, _ = UserProfile.objects.get_or_create(user=user)
    from_state = profile.lifecycle_state or derive_lifecycle_state(
        profile.approval_status, user.is_active,
    )
    # Let transition_user run outside our outer audit transaction for illegal
    # attempts so its rejected UserLifecycleAudit row survives the rollback.
    if (from_state, LifecycleState.DELETED) not in LEGAL_TRANSITIONS:
        raise IllegalLifecycleTransition(from_state, LifecycleState.DELETED)

    before = {
        'username': user.username,
        'email': user.email,
        'is_staff': user.is_staff,
        'is_superuser': user.is_superuser,
        'is_active': user.is_active,
        'lifecycle_state': from_state,
    }
    deleted_id = user.id
    deleted_username = user.username
    with transaction.atomic():
        profile = transition_user(
            user, LifecycleState.DELETED, actor=actor, reason='admin delete',
        )
        user.refresh_from_db(fields=['is_active'])
        AdminAuditEvent.objects.append(
            action=ACTION_ADMIN_USER_DELETE,
            actor=actor,
            target_type='user',
            target_id=deleted_id,
            target_repr=deleted_username,
            before=before,
            after={
                'deleted': True,
                'soft_deleted': True,
                'is_active': user.is_active,
                'lifecycle_state': profile.lifecycle_state,
                'deleted_at': profile.deleted_at.isoformat() if profile.deleted_at else None,
                **({'break_glass': True, 'break_glass_reason': break_glass_reason}
                   if break_glass_reason else {}),
            },
            request_metadata=request_metadata(request),
        )
    return deleted_id


# ---------------------------------------------------------------------------
# Chain verification.
# ---------------------------------------------------------------------------
@dataclass
class ChainVerification:
    ok: bool
    checked: int
    first_bad_seq: int | None = None
    reason: str = ''


def verify_chain(events=None) -> ChainVerification:
    """Walk the ledger in seq order, recomputing every hash.

    Detects any in-place tamper (payload edit, re-hash without relink,
    deleted or reordered rows) as a break at the first inconsistent event.
    """
    if events is None:
        events = AdminAuditEvent.objects.order_by('seq').iterator()
    prev_hash = ADMIN_AUDIT_GENESIS_HASH
    prev_seq = 0
    checked = 0
    for event in events:
        if event.seq != prev_seq + 1:
            return ChainVerification(
                ok=False, checked=checked, first_bad_seq=event.seq,
                reason=f'sequence gap: expected {prev_seq + 1}, found {event.seq}',
            )
        if event.prev_hash != prev_hash:
            return ChainVerification(
                ok=False, checked=checked, first_bad_seq=event.seq,
                reason='prev_hash does not match preceding event hash',
            )
        if event.compute_hash() != event.event_hash:
            return ChainVerification(
                ok=False, checked=checked, first_bad_seq=event.seq,
                reason='event payload does not match its recorded hash',
            )
        prev_hash = event.event_hash
        prev_seq = event.seq
        checked += 1
    return ChainVerification(ok=True, checked=checked)


# ---------------------------------------------------------------------------
# P4 — query-surface helpers: redaction, per-event chain status, derivations.
# ---------------------------------------------------------------------------
REDACTED = '[redacted]'

# Keys whose *string* value could carry a secret. The wrappers already store
# only safe flags (e.g. ``password_changed: True``), but the query surface must
# guarantee — defensively, for any future action — that no password/token/
# secret material is ever returned. We redact only string/bytes values under a
# sensitive key, so safe booleans (``password_changed``) and reasons
# (``break_glass_reason``) survive intact.
_SENSITIVE_KEY_RE = re.compile(
    r'password|passwd|secret|token|api[-_]?key|private[-_]?key|'
    r'credential|otp|totp|recovery[-_]?code|signing[-_]?key',
    re.IGNORECASE,
)


def redact_audit_payload(value):
    """Recursively redact secret-bearing string values from a JSON payload.

    A key matching :data:`_SENSITIVE_KEY_RE` whose value is a string/bytes is
    replaced with :data:`REDACTED`; everything else (booleans, ints, slug
    lists, nested structures) is preserved and recursed into.
    """
    if isinstance(value, dict):
        out = {}
        for key, val in value.items():
            if (isinstance(key, str) and _SENSITIVE_KEY_RE.search(key)
                    and isinstance(val, (str, bytes))):
                out[key] = REDACTED
            else:
                out[key] = redact_audit_payload(val)
        return out
    if isinstance(value, list):
        return [redact_audit_payload(v) for v in value]
    return value


def derive_outcome(event) -> str:
    """Classify an event as ``allowed`` / ``denied`` / ``failed``.

    Denied attempts are recorded via :data:`ACTION_ADMIN_POLICY_DENIED` (or an
    explicit ``after.outcome``); every other committed mutation is ``allowed``.
    """
    if event.action == ACTION_ADMIN_POLICY_DENIED:
        return 'denied'
    outcome = (event.after or {}).get('outcome')
    if outcome in ('denied', 'failed'):
        return outcome
    return 'allowed'


def derive_service_slug(event) -> str:
    """Best-effort service slug an event concerns, for display/filtering."""
    if event.target_type == 'tool':
        return event.target_id or ''
    if event.target_type == 'service_access_request' and ':' in (event.target_repr or ''):
        return event.target_repr.split(':', 1)[1]
    requested = (event.after or {}).get('requested_slugs')
    if isinstance(requested, list) and len(requested) == 1:
        return requested[0]
    return ''


def event_chain_status(event) -> dict:
    """Integrity status of a single event relative to its recorded chain.

    ``event_hash_valid`` — the stored hash matches a recompute of the payload
    (no in-place tamper). ``prev_hash_valid`` — the ``prev_hash`` matches the
    preceding event's hash (or genesis at ``seq == 1``). ``intact`` is both.
    A full-ledger walk is :func:`verify_chain`.
    """
    event_hash_valid = event.compute_hash() == event.event_hash
    prev = AdminAuditEvent.objects.filter(seq=event.seq - 1).first()
    expected_prev = prev.event_hash if prev else ADMIN_AUDIT_GENESIS_HASH
    prev_hash_valid = event.prev_hash == expected_prev
    return {
        'event_hash_valid': event_hash_valid,
        'prev_hash_valid': prev_hash_valid,
        'intact': event_hash_valid and prev_hash_valid,
    }
