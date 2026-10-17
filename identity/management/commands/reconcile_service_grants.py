"""
Management command: reconcile_service_grants

Applies declarative default service grants from the role_service_matrix to
all users with a UserProfile. STRICTLY ADDITIVE — never removes existing
approved grants. Only adds the grants that the matrix says a role should have.

Usage:
    python manage.py reconcile_service_grants
    python manage.py reconcile_service_grants --role engineer
    python manage.py reconcile_service_grants --account-type agent
    python manage.py reconcile_service_grants --dry-run

Output: safe counts and IDs only (no profile payloads, no service-request details).

Idempotent: running twice produces no change on the second run.

PLAT-317 durability: run this after any consolidation roll that modifies the
Tool catalog (e.g. after adding a new service slug) to ensure all roles that
should have it get the grant.

The 'grant' record created here is a direct addition to profile.enabled_tools
(the same path as AdminUserServicesView POST action='grant'). It is NOT a
ServiceAccessRequest — the matrix is the pre-approved authority for default
role grants and does not require per-user review.
"""
import logging

from django.core.management.base import BaseCommand

from identity.models import Tool, UserProfile
from identity.role_service_matrix import (
    RETIRED_SERVICE_SLUGS,
    get_default_services_for_role,
)

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Idempotently apply declarative default service grants per the SCLI-45 role matrix'

    def add_arguments(self, parser):
        parser.add_argument(
            '--role', type=str, default=None,
            help='Only process profiles with this service_grants_role value'
        )
        parser.add_argument(
            '--account-type', type=str, default=None, choices=['human', 'agent'],
            help='Only process profiles with this account_type'
        )
        parser.add_argument(
            '--dry-run', action='store_true', default=False,
            help='Show what would be added without writing to the database'
        )

    def handle(self, *args, **options):
        role_filter = options['role']
        account_type_filter = options['account_type']
        dry_run = options['dry_run']

        if dry_run:
            self.stdout.write(self.style.WARNING('[DRY RUN] No changes will be written.'))

        # Build a map of active tool slugs → Tool objects for fast lookup.
        # We only grant active tools; if a slug in the matrix has no active Tool
        # record, we skip and warn (service not yet seeded or renamed).
        active_tools = {t.slug: t for t in Tool.objects.filter(is_active=True)}
        retired_present = RETIRED_SERVICE_SLUGS & set(active_tools.keys())
        if retired_present:
            self.stdout.write(self.style.WARNING(
                f'[WARN] Retired slug(s) still in Tool catalog: {sorted(retired_present)}'
            ))

        qs = UserProfile.objects.select_related('user').prefetch_related('enabled_tools')
        if role_filter:
            qs = qs.filter(service_grants_role=role_filter)
        if account_type_filter:
            qs = qs.filter(account_type=account_type_filter)

        total = qs.count()
        self.stdout.write(f'Processing {total} profile(s)...')

        grants_added = 0
        profiles_updated = 0
        skipped_slugs: dict[str, int] = {}  # slug → count of skips (not in catalog)

        for profile in qs.iterator(chunk_size=200):
            role = profile.service_grants_role
            account_type = profile.account_type
            expected_slugs = get_default_services_for_role(role, account_type=account_type)

            current_slugs = set(profile.enabled_tools.values_list('slug', flat=True))
            missing_slugs = expected_slugs - current_slugs

            if not missing_slugs:
                continue  # already consistent — idempotent no-op

            # Resolve missing slugs to active Tool objects; skip any not in catalog
            tools_to_add = []
            for slug in missing_slugs:
                if slug in RETIRED_SERVICE_SLUGS:
                    skipped_slugs[slug] = skipped_slugs.get(slug, 0) + 1
                    continue
                if slug not in active_tools:
                    skipped_slugs[slug] = skipped_slugs.get(slug, 0) + 1
                    continue
                tools_to_add.append(active_tools[slug])

            if not tools_to_add:
                continue

            added_slugs = [t.slug for t in tools_to_add]
            if dry_run:
                self.stdout.write(
                    f'  [DRY] user_id={profile.user_id} role={role!r} '
                    f'account_type={account_type} would_add={sorted(added_slugs)}'
                )
            else:
                profile.enabled_tools.add(*tools_to_add)
                logger.info(
                    'reconcile_service_grants: user_id=%s role=%r account_type=%s added=%s',
                    profile.user_id, role, account_type, sorted(added_slugs),
                )

            grants_added += len(tools_to_add)
            profiles_updated += 1

        if skipped_slugs:
            self.stdout.write(self.style.WARNING(
                f'[WARN] Skipped slugs not in active catalog (not yet seeded or retired): {dict(skipped_slugs)}'
            ))

        verb = 'Would add' if dry_run else 'Added'
        self.stdout.write(self.style.SUCCESS(
            f'Done. {verb} {grants_added} grant(s) across {profiles_updated}/{total} profile(s).'
        ))
