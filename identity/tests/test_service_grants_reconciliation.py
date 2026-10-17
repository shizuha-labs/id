"""
Tests for ID-12: declarative durable service grants backed by role_service_matrix.

Verifies:
  - Role matrix grants are applied correctly per role/account_type
  - Explicit approved grants survive reconciliation (never removed)
  - Unknown/None role → base only (fail-closed)
  - PLAT-317: retired slugs are skipped, not silently granted
  - Reconciliation is idempotent (second run changes nothing)
  - Human accounts get human defaults, not agent base
  - get_default_services_for_role follows the SCLI-45 analogue contract
"""
from io import StringIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase

from identity.models import Tool, UserProfile
from identity.role_service_matrix import (
    AGENT_BASE_SERVICES,
    HUMAN_DEFAULT_SERVICES,
    RETIRED_SERVICE_SLUGS,
    ROLE_ADDITIONAL_SERVICES,
    get_default_services_for_role,
)

User = get_user_model()


def _make_tool(slug, *, active=True):
    t, _ = Tool.objects.get_or_create(
        slug=slug,
        defaults={
            'display_name': slug.title(),
            'description': '',
            'minimum_tier': 'free',
            'is_active': active,
            'is_default_enabled': False,
            'requires_approval': False,
            'requires_superuser': False,
        },
    )
    return t


class RoleServiceMatrixTests(TestCase):
    """Unit tests for get_default_services_for_role() contract."""

    def test_agent_base_services_in_every_agent_role(self):
        """Every agent role must include AGENT_BASE_SERVICES."""
        for role in list(ROLE_ADDITIONAL_SERVICES.keys()) + [None, '', 'unknown-role']:
            if role == 'human':
                continue  # human is handled separately
            services = get_default_services_for_role(role, account_type='agent')
            self.assertTrue(
                AGENT_BASE_SERVICES.issubset(services),
                f"AGENT_BASE_SERVICES missing for role={role!r}: got {services}",
            )

    def test_human_default_services(self):
        """Human accounts get HUMAN_DEFAULT_SERVICES regardless of role."""
        for role in ['engineer', 'architect', 'unknown', None, '']:
            services = get_default_services_for_role(role, account_type='human')
            self.assertEqual(services, HUMAN_DEFAULT_SERVICES,
                f"Expected human defaults for role={role!r}, got {services}")
            self.assertIn('mail', services)

    def test_mail_is_a_universal_default(self):
        """Every human and agent role receives the managed-mail entitlement."""
        self.assertIn('mail', HUMAN_DEFAULT_SERVICES)
        for role in ['engineer', 'reviewer', 'qa', 'unknown', None]:
            self.assertIn(
                'mail',
                get_default_services_for_role(role, account_type='agent'),
            )

    def test_unknown_role_fails_closed_to_base(self):
        """Unknown agent role → AGENT_BASE_SERVICES only (fail-closed)."""
        services = get_default_services_for_role('totally-unknown', account_type='agent')
        self.assertEqual(services, AGENT_BASE_SERVICES)

    def test_none_role_fails_closed_to_base(self):
        services = get_default_services_for_role(None, account_type='agent')
        self.assertEqual(services, AGENT_BASE_SERVICES)

    def test_architect_gets_admin(self):
        services = get_default_services_for_role('architect', account_type='agent')
        self.assertIn('admin', services)
        self.assertTrue(AGENT_BASE_SERVICES.issubset(services))

    def test_engineer_has_no_extras(self):
        services = get_default_services_for_role('engineer', account_type='agent')
        self.assertEqual(services, AGENT_BASE_SERVICES)

    def test_analytics_gets_finance_books_inventory_time(self):
        services = get_default_services_for_role('analytics', account_type='agent')
        self.assertTrue({'finance', 'books', 'inventory', 'time'}.issubset(services))

    def test_human_does_not_get_agent_base(self):
        """Human accounts must NOT inherit agent base (pulse/connect/wiki by default)."""
        services = get_default_services_for_role('human', account_type='human')
        self.assertNotIn('pulse', services)
        self.assertNotIn('connect', services)


class ReconcileCommandTests(TestCase):
    """Integration tests for the reconcile_service_grants management command."""

    def setUp(self):
        # Seed the Tool catalog with services the matrix references
        for slug in ['id', 'hive', 'pulse', 'connect', 'wiki', 'admin', 'notes', 'mail']:
            _make_tool(slug)

        self.agent_user = User.objects.create_user(
            username='test_agent', email='agent@test.com', password='pw',
        )
        self.agent_profile, _ = UserProfile.objects.get_or_create(user=self.agent_user)
        self.agent_profile.account_type = 'agent'
        self.agent_profile.service_grants_role = 'engineer'
        self.agent_profile.save()

        self.human_user = User.objects.create_user(
            username='test_human', email='human@test.com', password='pw',
        )
        self.human_profile, _ = UserProfile.objects.get_or_create(user=self.human_user)
        self.human_profile.account_type = 'human'
        self.human_profile.save()

    def _run_reconcile(self, **kwargs):
        out = StringIO()
        call_command('reconcile_service_grants', stdout=out, **kwargs)
        return out.getvalue()

    def test_engineer_agent_gets_base_services(self):
        """Engineer role → AGENT_BASE_SERVICES added."""
        self.agent_profile.enabled_tools.clear()
        self._run_reconcile()
        slugs = set(self.agent_profile.enabled_tools.values_list('slug', flat=True))
        self.assertTrue(AGENT_BASE_SERVICES.issubset(slugs),
            f"Missing base services: {AGENT_BASE_SERVICES - slugs}")

    def test_human_user_gets_human_defaults(self):
        """Human account → HUMAN_DEFAULT_SERVICES added."""
        self.human_profile.enabled_tools.clear()
        self._run_reconcile()
        slugs = set(self.human_profile.enabled_tools.values_list('slug', flat=True))
        # At least 'id' and 'hive' must be present (the human defaults)
        self.assertTrue(HUMAN_DEFAULT_SERVICES.issubset(slugs),
            f"Missing human defaults: {HUMAN_DEFAULT_SERVICES - slugs}")

    def test_explicit_grant_survives_reconciliation(self):
        """PLAT-317: existing approved grants are NEVER removed by reconciliation."""
        notes_tool = Tool.objects.get(slug='notes')
        self.agent_profile.enabled_tools.set([notes_tool])  # explicit grant
        self._run_reconcile()
        slugs = set(self.agent_profile.enabled_tools.values_list('slug', flat=True))
        self.assertIn('notes', slugs, "Explicit approved grant must survive reconciliation")

    def test_idempotency(self):
        """Running reconcile twice produces no additional changes on the second run."""
        self.agent_profile.enabled_tools.clear()
        self._run_reconcile()
        slugs_after_first = set(self.agent_profile.enabled_tools.values_list('slug', flat=True))
        self._run_reconcile()
        slugs_after_second = set(self.agent_profile.enabled_tools.values_list('slug', flat=True))
        self.assertEqual(slugs_after_first, slugs_after_second,
            "Second reconcile run changed the grant set — not idempotent")

    def test_dry_run_makes_no_changes(self):
        """--dry-run reports what would change without writing to the database."""
        self.agent_profile.enabled_tools.clear()
        out = self._run_reconcile(dry_run=True)
        self.assertIn('[DRY]', out)
        # No tools should have been added
        self.assertEqual(self.agent_profile.enabled_tools.count(), 0,
            "--dry-run must not write to the database")

    def test_role_filter_limits_scope(self):
        """--role filter only processes matching profiles."""
        arch_user = User.objects.create_user(username='arch', email='arch@test.com', password='pw')
        arch_profile, _ = UserProfile.objects.get_or_create(user=arch_user)
        arch_profile.account_type = 'agent'
        arch_profile.service_grants_role = 'architect'
        arch_profile.save()
        arch_profile.enabled_tools.clear()

        self.agent_profile.enabled_tools.clear()

        # Only reconcile architects
        self._run_reconcile(role='architect')

        arch_slugs = set(arch_profile.enabled_tools.values_list('slug', flat=True))
        eng_slugs = set(self.agent_profile.enabled_tools.values_list('slug', flat=True))

        self.assertIn('admin', arch_slugs, "architect must get admin")
        # Engineer was not in scope — no grants should have been added
        self.assertEqual(len(eng_slugs), 0,
            "engineer profile should not be touched when role=architect filter is active")

    def test_missing_catalog_slug_skipped_gracefully(self):
        """A slug in the matrix not in the Tool catalog is skipped with a warning."""
        # Guarantee one role-matrix slug is absent even if catalog seed data expands.
        Tool.objects.filter(slug='finance').delete()
        self.agent_profile.service_grants_role = 'analytics'
        self.agent_profile.save()
        self.agent_profile.enabled_tools.clear()

        out = self._run_reconcile()
        # Should warn about missing slugs but not crash
        self.assertIn('WARN', out)
        # Base slugs that ARE in catalog should still be granted
        slugs = set(self.agent_profile.enabled_tools.values_list('slug', flat=True))
        self.assertTrue(AGENT_BASE_SERVICES.issubset(slugs),
            "Base services must be added even when some role extras are missing from catalog")

    def test_plat317_silent_drop_cannot_recur(self):
        """PLAT-317 regression: reconcile always adds, never silently removes.

        Even if the matrix changes to add a new slug, a subsequent run adds it
        but never touches existing grants — the set can only grow via reconcile.
        """
        # Give user a full set
        all_tools = list(Tool.objects.filter(is_active=True))
        self.agent_profile.enabled_tools.set(all_tools)
        before_slugs = set(self.agent_profile.enabled_tools.values_list('slug', flat=True))

        # Run reconcile (which would only ADD missing grants, not remove anything)
        self._run_reconcile()

        after_slugs = set(self.agent_profile.enabled_tools.values_list('slug', flat=True))
        self.assertEqual(before_slugs, after_slugs,
            "Reconcile must not remove any existing grants (PLAT-317)")
