"""User lifecycle FSM (ID-32, HLD ID-3 §4.1/§4.3/§4.6).

Single transition function every lifecycle mutation routes through. Enforces
legal transitions server-side (invalid transitions raise, never silently
coerce), keeps the legacy ``User.is_active`` + ``UserProfile.approval_status``
fields in sync for back-compat, and writes a ``UserLifecycleAudit`` row per
attempt (actor, subject, from→to, timestamp, outcome — fields per the ID-25
decision).

ID-39 adds the P3 transactional outbox event row in this function; token-epoch
revocation on deactivate/delete remains P4 and must reuse ID-1's
``revoke_all_user_tokens()`` rather than forking revocation logic.
"""
import logging
import re

from django.db import transaction
from django.utils import timezone

logger = logging.getLogger(__name__)


class LifecycleState:
    PENDING = 'pending'
    ACTIVE = 'active'
    DENIED = 'denied'
    DEACTIVATED = 'deactivated'
    DELETED = 'deleted'

    CHOICES = [
        (PENDING, 'Pending'),
        (ACTIVE, 'Active'),
        (DENIED, 'Denied'),
        (DEACTIVATED, 'Deactivated'),
        (DELETED, 'Deleted'),
    ]
    ALL = {PENDING, ACTIVE, DENIED, DEACTIVATED, DELETED}


# HLD §4.1: pending → active/denied; active ↔ deactivated (reactivate);
# §4.6: denied → active (re-approve). Soft-delete from active/deactivated/denied.
# ``deleted`` is terminal in this slice — reactivation from deleted is NOT
# legal (hard-purge and cross-service cleanup are the P3 slice's concern).
LEGAL_TRANSITIONS = {
    (LifecycleState.PENDING, LifecycleState.ACTIVE),        # approve
    (LifecycleState.PENDING, LifecycleState.DENIED),        # deny
    (LifecycleState.ACTIVE, LifecycleState.DEACTIVATED),    # deactivate
    (LifecycleState.ACTIVE, LifecycleState.DELETED),        # soft-delete
    (LifecycleState.DEACTIVATED, LifecycleState.ACTIVE),    # reactivate
    (LifecycleState.DEACTIVATED, LifecycleState.DELETED),   # soft-delete
    (LifecycleState.DENIED, LifecycleState.ACTIVE),         # re-approve (§4.6)
    (LifecycleState.DENIED, LifecycleState.DELETED),        # soft-delete
}

# lifecycle_state → (approval_status, is_active) legacy-field sync.
_LEGACY_SYNC = {
    LifecycleState.PENDING: ('pending', False),
    LifecycleState.ACTIVE: ('approved', True),
    LifecycleState.DENIED: ('denied', False),
    LifecycleState.DEACTIVATED: ('approved', False),
    LifecycleState.DELETED: ('approved', False),
}


class IllegalLifecycleTransition(Exception):
    """Raised when a lifecycle transition is not in LEGAL_TRANSITIONS."""

    def __init__(self, from_state: str, to_state: str):
        self.from_state = from_state
        self.to_state = to_state
        super().__init__(f'Illegal lifecycle transition: {from_state} -> {to_state}')


def derive_lifecycle_state(approval_status: str, is_active: bool) -> str:
    """Map legacy (approval_status, is_active) to a lifecycle state.

    Used by the backfill migration and anywhere a pre-FSM row is encountered.
    """
    if approval_status == 'denied':
        return LifecycleState.DENIED
    if approval_status == 'pending':
        return LifecycleState.PENDING
    return LifecycleState.ACTIVE if is_active else LifecycleState.DEACTIVATED


def _record_audit(*, user, actor, from_state, to_state, reason, outcome):
    from .models import UserLifecycleAudit

    try:
        UserLifecycleAudit.objects.create(
            user=user,
            actor_id=getattr(actor, 'id', None),
            from_state=from_state,
            to_state=to_state,
            reason=reason or '',
            outcome=outcome,
        )
    except Exception:  # noqa: BLE001 — audit failure must not mask the caller's error path
        logger.exception(
            'lifecycle audit write failed (user=%s %s->%s outcome=%s)',
            getattr(user, 'id', None), from_state, to_state, outcome,
        )


def lifecycle_event_type(from_state: str, to_state: str):
    """Return the cross-service event type for a lifecycle edge, if any."""
    from .models import UserLifecycleEvent

    if to_state == LifecycleState.DEACTIVATED:
        return UserLifecycleEvent.EVENT_DEACTIVATED
    if to_state == LifecycleState.DELETED:
        return UserLifecycleEvent.EVENT_DELETED
    if to_state == LifecycleState.ACTIVE and from_state in {LifecycleState.DEACTIVATED, LifecycleState.DENIED}:
        return UserLifecycleEvent.EVENT_REACTIVATED
    return None


def _enqueue_lifecycle_event(*, user, from_state, to_state, reason):
    """Create the ID-39 outbox row inside the caller's transaction.

    This intentionally does not catch database errors: enqueue failure must abort
    the lifecycle mutation so we never commit a user state change without its
    cleanup event.
    """
    from .models import UserLifecycleEvent, UserLifecycleEventDelivery

    event_type = lifecycle_event_type(from_state, to_state)
    if not event_type:
        return None
    event = UserLifecycleEvent.objects.create(
        event_type=event_type,
        user_id=user.id,
        user_email=(user.email or ''),
        user_username=(user.username or ''),
        from_state=from_state,
        to_state=to_state,
        reason=reason or '',
        payload={
            'event_type': event_type,
            'user_id': user.id,
            'email': user.email or '',
            'username': user.username or '',
            'from_state': from_state,
            'to_state': to_state,
            'reason': reason or '',
        },
    )
    consumers = [UserLifecycleEventDelivery.CONSUMER_PULSE]
    # The profile transition signal emits the corresponding user.activated
    # event for reactivation, so do not deliver the legacy reactivated event to
    # Mail a second time.  Deactivate/delete still fan out to both consumers.
    if event_type != UserLifecycleEvent.EVENT_REACTIVATED:
        consumers.append(UserLifecycleEventDelivery.CONSUMER_MAIL)
    UserLifecycleEventDelivery.objects.bulk_create([
        UserLifecycleEventDelivery(event=event, consumer=consumer)
        for consumer in consumers
    ])
    return event


def mailbox_localpart_for_username(username):
    """Return the deterministic managed-mailbox local part for a username.

    PLAT-5731: this is the canonical local-part derivation used by
    ``mailbox_address_for_user``. It is intentionally NOT injective — both
    ``alice`` and ``alice@gmail.com`` derive ``alice`` — so every creation path
    must consult ``mailbox_localpart_taken`` on the DERIVED local part (not the
    raw username) before granting a mailbox, or two accounts authenticate as the
    same signed mail identity.
    """
    username = (username or '').strip().lower()
    # Legacy/imported identities may use their external email as username.
    # Preserve the familiar local part rather than producing a double-@ address.
    return username.split('@', 1)[0]


def mailbox_localpart_taken(localpart, exclude_user_id=None):
    """True if any user's username derives the same managed-mailbox local part.

    PLAT-5731: ``alice`` and ``alice@gmail.com`` are distinct raw usernames that
    both derive the mailbox local part ``alice`` — a raw ``username__iexact``
    uniqueness check misses the ``@``-containing form. This guard matches both
    shapes so a colliding pair can never both hold a signed mail identity.
    """
    from django.contrib.auth import get_user_model
    from django.db.models import Q

    User = get_user_model()
    localpart = (localpart or '').strip().lower()
    if not localpart:
        return False
    qs = User.objects.filter(
        Q(username__iexact=localpart) |
        Q(username__iregex=r'^{0}@'.format(re.escape(localpart)))
    )
    if exclude_user_id:
        qs = qs.exclude(id=exclude_user_id)
    return qs.exists()


def mailbox_address_for_user(user):
    """Return the deterministic managed mailbox for an ID username."""
    mailbox_localpart = mailbox_localpart_for_username(getattr(user, 'username', ''))
    domain = __import__('os').environ.get('SHIZUHA_MAIL_DOMAIN', 'shizuha.com').strip().lower()
    return f'{mailbox_localpart}@{domain}'


def account_type_for_user(user):
    """Return the authoritative lifecycle account type for an ID identity.

    ``UserProfile.account_type`` is the identity source of truth.  Read it from
    the database instead of using username/email heuristics or a possibly stale
    reverse-relation cache held by ``User`` during profile signals.
    """
    from .models import UserProfile

    account_type = (
        UserProfile.objects.filter(user_id=user.id)
        .values_list('account_type', flat=True)
        .first()
    )
    return 'agent' if account_type == 'agent' else 'human'


def enqueue_user_activated(*, user, from_state=LifecycleState.PENDING, reason=''):
    """Transactionally announce that an ID identity became mail-eligible.

    This is called by the UserProfile transition signal so legacy creation
    paths that have not yet been moved to ``transition_user`` cannot silently
    skip default mailbox provisioning.
    """
    from .models import UserLifecycleEvent, UserLifecycleEventDelivery

    mailbox_email = mailbox_address_for_user(user)
    account_type = account_type_for_user(user)
    event = UserLifecycleEvent.objects.create(
        event_type=UserLifecycleEvent.EVENT_ACTIVATED,
        user_id=user.id,
        user_email=user.email or '',
        user_username=user.username or '',
        from_state=from_state or LifecycleState.PENDING,
        to_state=LifecycleState.ACTIVE,
        reason=reason or '',
        payload={
            'event_type': UserLifecycleEvent.EVENT_ACTIVATED,
            'user_id': user.id,
            'email': user.email or '',
            'username': user.username or '',
            'mailbox_email': mailbox_email,
            'account_type': account_type,
            'from_state': from_state or LifecycleState.PENDING,
            'to_state': LifecycleState.ACTIVE,
            'reason': reason or '',
        },
    )
    UserLifecycleEventDelivery.objects.create(
        event=event,
        consumer=UserLifecycleEventDelivery.CONSUMER_MAIL,
    )
    # Operator 2026-08-19: every new human gets one hibernated personal
    # Shizuha. Fail-soft and after commit so a Hive blip cannot roll back
    # activation / mailbox outbox.
    notify_payload = {
        'user_id': int(user.id),
        'username': user.username or '',
        'email': user.email or '',
        'is_staff': bool(getattr(user, 'is_staff', False)),
        'is_superuser': bool(getattr(user, 'is_superuser', False)),
        'account_type': account_type,
    }

    def _notify_hive_default_agent():
        from .personal_agent_notify import notify_hive_default_personal_agent
        notify_hive_default_personal_agent(**notify_payload)

    transaction.on_commit(_notify_hive_default_agent)
    return event


def enqueue_user_deactivated(*, user, from_state=LifecycleState.ACTIVE, reason=''):
    """Transactionally announce that an ID identity is no longer mail-eligible.

    Mirrors ``enqueue_user_activated`` for the deactivation edge. This is the
    reconciliation path used when a ``user.deactivated``/``user.deleted`` event
    was never enqueued (or its Mail delivery was lost), so a managed MailAccount
    would otherwise stay ``is_active`` forever and drift the mailbox-inventory
    count above the active-identity count (deploy-id-mail-lifecycle gate).
    """
    from .models import UserLifecycleEvent, UserLifecycleEventDelivery

    mailbox_email = mailbox_address_for_user(user)
    event = UserLifecycleEvent.objects.create(
        event_type=UserLifecycleEvent.EVENT_DEACTIVATED,
        user_id=user.id,
        user_email=user.email or '',
        user_username=user.username or '',
        from_state=from_state or LifecycleState.ACTIVE,
        to_state=LifecycleState.DEACTIVATED,
        reason=reason or '',
        payload={
            'event_type': UserLifecycleEvent.EVENT_DEACTIVATED,
            'user_id': user.id,
            'email': user.email or '',
            'username': user.username or '',
            'mailbox_email': mailbox_email,
            'from_state': from_state or LifecycleState.ACTIVE,
            'to_state': LifecycleState.DEACTIVATED,
            'reason': reason or '',
        },
    )
    UserLifecycleEventDelivery.objects.create(
        event=event,
        consumer=UserLifecycleEventDelivery.CONSUMER_MAIL,
    )
    return event


def transition_user(user, to_state: str, *, actor=None, reason: str = ''):
    """Apply a lifecycle transition to ``user``; the ONLY sanctioned mutation path.

    Atomically (row-locked): validates legality, updates
    ``UserProfile.lifecycle_state`` + timestamps, and syncs the legacy
    ``approval_status`` / ``User.is_active`` fields. Writes an audit row for the
    applied transition; illegal attempts write a ``rejected`` audit row and
    raise :class:`IllegalLifecycleTransition` (INV-1/INV-4 — reject, never
    coerce).

    Returns the updated profile.
    """
    from .models import UserProfile

    if to_state not in LifecycleState.ALL:
        raise IllegalLifecycleTransition('<any>', to_state)

    try:
        with transaction.atomic():
            profile, _ = UserProfile.objects.select_for_update().get_or_create(user=user)
            from_state = profile.lifecycle_state or derive_lifecycle_state(
                profile.approval_status, user.is_active,
            )

            if (from_state, to_state) not in LEGAL_TRANSITIONS:
                raise IllegalLifecycleTransition(from_state, to_state)

            now = timezone.now()
            approval_status, is_active = _LEGACY_SYNC[to_state]

            # Save the User FIRST: the post_save `save_user_profile` signal
            # full-saves the user's cached profile instance.  Evict that
            # relation before saving so callers which persisted policy through
            # a separately queried/locked profile cannot have it clobbered by
            # a stale cached instance (MAIL-120).
            if user.is_active != is_active:
                user._state.fields_cache.pop('profile', None)
                user.is_active = is_active
                user.save(update_fields=['is_active'])

            profile.lifecycle_state = to_state
            profile.approval_status = approval_status
            update_fields = ['lifecycle_state', 'approval_status', 'updated_at']
            if to_state == LifecycleState.DEACTIVATED:
                profile.deactivated_at = now
                update_fields.append('deactivated_at')
            elif to_state == LifecycleState.DELETED:
                profile.deleted_at = now
                update_fields.append('deleted_at')
            elif to_state == LifecycleState.ACTIVE:
                profile.deactivated_at = None
                update_fields.append('deactivated_at')
                # Operator 2026-07-11: grant a newly-active HUMAN account its default
                # consumer services so the very first login token carries them — above
                # all `connect`, without which the user can't see their conversations
                # (incl. their personal Shizuha agent) or use the social platform.
                # Union-only (never downgrades a custom set); agents get their services
                # via the fleet provisioner. Env-tunable via USER_DEFAULT_SERVICES.
                if getattr(profile, 'account_type', 'human') != 'agent':
                    try:
                        import logging as _lg
                        import os as _os
                        from .models import Tool as _Tool
                        _svc = _os.environ.get(
                            'USER_DEFAULT_SERVICES',
                            'id,home,connect,hive,drive,mail,notes,wiki,pulse,time')
                        _slugs = [s.strip() for s in _svc.split(',') if s.strip()]
                        _tools = list(_Tool.objects.filter(slug__in=_slugs, is_active=True))
                        if _tools:
                            profile.enabled_tools.add(*_tools)
                    except Exception:
                        _lg.getLogger(__name__).exception(
                            'default consumer service grant failed for user %s',
                            getattr(user, 'id', None))
            profile.save(update_fields=update_fields)
            # Sync the user's cached profile relation so a later user.save()
            # (signal full-save) can't resurrect pre-transition values.
            user._state.fields_cache.pop('profile', None)

            _record_audit(
                user=user, actor=actor, from_state=from_state, to_state=to_state,
                reason=reason, outcome='applied',
            )
            _enqueue_lifecycle_event(
                user=user, from_state=from_state, to_state=to_state, reason=reason,
            )

            # ID-41 (HLD ID-3 §6 P4 / gap L-6): a deactivate or soft-delete must
            # immediately kill the user's live sessions — every access/refresh
            # token minted before this transition stops validating. REUSE ID-1's
            # revoke_all_user_tokens (do NOT fork revocation logic): it advances
            # UserProfile.access_revoked_before (the fail-closed access cutoff the
            # authentication path enforces), purges push tokens (ID-21) and
            # blacklists refresh tokens. Called INSIDE this atomic block so
            # revocation is atomic with the state change — a transition rollback
            # also rolls back the cutoff bump, and a revocation failure aborts the
            # whole transition (a removed user is NEVER left with live tokens).
            # Reactivation (DEACTIVATED->ACTIVE) needs nothing here: the cutoff
            # persists, so pre-deactivation tokens stay dead while fresh logins
            # mint iat>cutoff tokens that validate.
            if to_state in (LifecycleState.DEACTIVATED, LifecycleState.DELETED):
                from .views import revoke_all_user_tokens
                from .invariants import record_lifecycle_revocation

                try:
                    revoke_all_user_tokens(user)
                except Exception:
                    # Fail-loud + fail-closed: record the failure metric (survives
                    # the rollback — the Redis write is non-transactional) so the
                    # Alertmanager/critical-alert-notifier path DMs the on-call
                    # lead, log CRITICAL, then re-raise to abort the transition.
                    record_lifecycle_revocation('failure')
                    logger.critical(
                        'ID-41 lifecycle revocation FAILED for user=%s %s->%s — '
                        'transition ABORTED (fail-closed; a removed user must not '
                        'keep live tokens); actor=%s',
                        user.id, from_state, to_state, getattr(actor, 'id', None),
                    )
                    raise
                # Count success only after the outer transaction commits, so a
                # later rollback can't leave a phantom success in the series.
                transaction.on_commit(lambda: record_lifecycle_revocation('success'))
    except IllegalLifecycleTransition as exc:
        # Outside the atomic block so the rejected-attempt audit row survives
        # the rollback (INV-1: rejected attempts are audited too).
        _record_audit(
            user=user, actor=actor, from_state=exc.from_state, to_state=exc.to_state,
            reason=reason, outcome='rejected',
        )
        raise

    logger.info(
        'lifecycle transition applied: user=%s %s->%s actor=%s',
        user.id, from_state, to_state, getattr(actor, 'id', None),
    )
    return profile
