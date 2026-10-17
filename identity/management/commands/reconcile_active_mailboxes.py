"""Create durable activation events for active identities missing one."""

from django.core.management.base import BaseCommand
from django.db import transaction

from identity.lifecycle import (
    LifecycleState,
    account_type_for_user,
    enqueue_user_activated,
    mailbox_address_for_user,
)
from identity.models import UserLifecycleEvent, UserLifecycleEventDelivery, UserProfile


class Command(BaseCommand):
    help = "Enqueue one user.activated event for every active approved ID user that lacks one."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--limit", type=int, default=0)

    def handle(self, *args, **options):
        qs = (
            UserProfile.objects.select_related("user")
            .filter(
                lifecycle_state=LifecycleState.ACTIVE,
                approval_status="approved",
                user__is_active=True,
            )
            .order_by("user_id")
        )
        profiles = list(qs)
        if options["limit"] > 0:
            profiles = profiles[:options["limit"]]

        missing = 0
        repairable = 0
        replayable = 0
        for profile in profiles:
            event = UserLifecycleEvent.objects.filter(
                event_type=UserLifecycleEvent.EVENT_ACTIVATED,
                user_id=profile.user_id,
            ).order_by('-created_at').first()
            if not event:
                missing += 1
                continue
            delivery = event.deliveries.filter(
                consumer=UserLifecycleEventDelivery.CONSUMER_MAIL,
            ).first()
            payload = event.payload or {}
            payload_is_stale = (
                payload.get('mailbox_email') != mailbox_address_for_user(profile.user)
                or payload.get('account_type') != account_type_for_user(profile.user)
            )
            if payload_is_stale:
                if delivery and delivery.status != UserLifecycleEvent.STATUS_PUBLISHED:
                    repairable += 1
                else:
                    replayable += 1
        self.stdout.write(
            f'missing_activation_events={missing} repairable_events={repairable} '
            f'replayable_events={replayable} '
            f'dry_run={options["dry_run"]}'
        )
        if options["dry_run"]:
            return

        created = repaired = 0
        for profile in profiles:
            with transaction.atomic():
                event = UserLifecycleEvent.objects.select_for_update().filter(
                    event_type=UserLifecycleEvent.EVENT_ACTIVATED,
                    user_id=profile.user_id,
                ).order_by('-created_at').first()
                if not event:
                    enqueue_user_activated(
                        user=profile.user,
                        from_state=LifecycleState.ACTIVE,
                        reason="active identity mailbox reconciliation",
                    )
                    created += 1
                    continue
                delivery = event.deliveries.select_for_update().filter(
                    consumer=UserLifecycleEventDelivery.CONSUMER_MAIL,
                ).first()
                desired_mailbox = mailbox_address_for_user(profile.user)
                desired_account_type = account_type_for_user(profile.user)
                payload = dict(event.payload or {})
                payload_is_stale = (
                    payload.get('mailbox_email') != desired_mailbox
                    or payload.get('account_type') != desired_account_type
                )
                if not payload_is_stale:
                    continue
                if delivery and delivery.status != UserLifecycleEvent.STATUS_PUBLISHED:
                    payload = dict(event.payload or {})
                    payload['mailbox_email'] = desired_mailbox
                    payload['account_type'] = desired_account_type
                    event.payload = payload
                    event.save(update_fields=['payload', 'updated_at'])
                    delivery.status = UserLifecycleEvent.STATUS_PENDING
                    delivery.next_attempt_at = None
                    delivery.last_error = ''
                    delivery.save(update_fields=[
                        'status', 'next_attempt_at', 'last_error', 'updated_at',
                    ])
                    repaired += 1
                    continue
                enqueue_user_activated(
                    user=profile.user,
                    from_state=LifecycleState.ACTIVE,
                    reason="active identity mailbox account-type reconciliation",
                )
                created += 1
        self.stdout.write(f"created={created} repaired={repaired}")
