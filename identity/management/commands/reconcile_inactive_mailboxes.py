"""Create durable deactivation events for inactive identities missing one."""

from django.core.management.base import BaseCommand
from django.db import transaction

from identity.lifecycle import (
    LifecycleState,
    enqueue_user_deactivated,
)
from identity.models import UserLifecycleEvent, UserLifecycleEventDelivery, UserProfile


class Command(BaseCommand):
    help = (
        "Enqueue one user.deactivated event for every inactive ID user that has "
        "an active managed mailbox but lacks a deactivation event."
    )

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--limit", type=int, default=0)

    def _has_activation(self, user_id):
        return UserLifecycleEvent.objects.filter(
            event_type=UserLifecycleEvent.EVENT_ACTIVATED,
            user_id=user_id,
        ).exists()

    def _has_deactivation(self, user_id):
        return UserLifecycleEvent.objects.filter(
            event_type__in=[
                UserLifecycleEvent.EVENT_DEACTIVATED,
                UserLifecycleEvent.EVENT_DELETED,
            ],
            user_id=user_id,
        ).exists()

    def handle(self, *args, **options):
        # Inactive identities: anything that is not an active, approved,
        # enabled user. These are the identities whose managed MailAccount
        # should have been disabled by a user.deactivated/user.deleted event.
        qs = (
            UserProfile.objects.select_related("user")
            .exclude(
                lifecycle_state=LifecycleState.ACTIVE,
                approval_status="approved",
                user__is_active=True,
            )
            .order_by("user_id")
        )
        profiles = list(qs)
        if options["limit"] > 0:
            profiles = profiles[: options["limit"]]

        missing = 0
        for profile in profiles:
            if self._has_deactivation(profile.user_id):
                continue
            # Only identities that were ever activated have a managed mailbox
            # to disable; never-activated identities have no MailAccount.
            if self._has_activation(profile.user_id):
                missing += 1
        self.stdout.write(
            f'missing_deactivation_events={missing} '
            f'dry_run={options["dry_run"]}'
        )
        if options["dry_run"]:
            return

        created = 0
        for profile in profiles:
            with transaction.atomic():
                if self._has_deactivation(profile.user_id):
                    continue
                if not self._has_activation(profile.user_id):
                    continue
                enqueue_user_deactivated(
                    user=profile.user,
                    from_state=profile.lifecycle_state or LifecycleState.ACTIVE,
                    reason="inactive identity mailbox reconciliation",
                )
                created += 1
        self.stdout.write(f"created={created}")
