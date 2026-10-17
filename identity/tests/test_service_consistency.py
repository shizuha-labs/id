"""
Regression tests for ID-11: grant/token/enforcement consistency (INV-5).

Verifies the invariant: effective_services == token enabled_services ==
id_admin_get_user_services report, for every access path.

Coverage:
  - Approved grant appears in token + admin report
  - Denied/pending grant absent from token and admin report
  - Revoked grant (removed from enabled_tools) absent from token
  - New/minimal user gets only least-privilege defaults (INV-3 regression)
  - Staff user gets all active services in token AND admin report
  - get_effective_services == token == admin (triangle consistency check)
  - Downstream enforcement contract: service absent from enabled_services
    would be correctly rejected by any service checking the claim
  - Token refresh re-reads live state (revocation propagates on next refresh)
"""
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from identity.models import Tool, UserProfile, ServiceAccessRequest
from identity.services import get_effective_services, get_default_new_user_service_slugs
from identity.views import get_tokens_for_user

User = get_user_model()
_projection_patcher = None


def setUpModule():
    global _projection_patcher
    _projection_patcher = mock.patch(
        'identity.views._fetch_membership_projection',
        return_value=({}, [], {}),
    )
    _projection_patcher.start()


def tearDownModule():
    _projection_patcher.stop()


def _make_tool(slug, *, active=True, requires_approval=False, requires_superuser=False,
               is_default_enabled=False):
    t, _ = Tool.objects.get_or_create(
        slug=slug,
        defaults={
            'display_name': slug.title(),
            'description': '',
            'minimum_tier': 'free',
            'is_active': active,
            'is_default_enabled': is_default_enabled,
            'requires_approval': requires_approval,
            'requires_superuser': requires_superuser,
        },
    )
    return t


def _decode_token(token_str):
    # Verify the actual platform RS256 signature, expiry and token type.
    from identity.agent_tokens import PlatformAccessToken
    return PlatformAccessToken(token_str).payload


class EffectiveServicesComputationTests(TestCase):
    """Unit tests for get_effective_services() in isolation."""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='alice', email='alice@test.com', password='pw'
        )
        self.profile, _ = UserProfile.objects.get_or_create(user=self.user)
        # Ensure default tools exist
        _make_tool('id', is_default_enabled=True)
        _make_tool('hive', is_default_enabled=True)
        _make_tool('notes', requires_approval=True)
        _make_tool('pulse', requires_approval=True)

    def test_new_user_gets_defaults_only(self):
        """INV-3 regression: new user with empty enabled_tools gets defaults only."""
        self.profile.enabled_tools.clear()
        slugs = get_effective_services(self.user)
        default_slugs = set(get_default_new_user_service_slugs())
        self.assertEqual(set(slugs), default_slugs)
        self.assertNotIn('notes', slugs)
        self.assertNotIn('pulse', slugs)

    def test_approved_grant_appears_in_effective(self):
        """Approved grant (tool added to enabled_tools) is included."""
        notes_tool = Tool.objects.get(slug='notes')
        self.profile.enabled_tools.set(
            list(Tool.objects.filter(slug__in=['id', 'hive'])) + [notes_tool]
        )
        slugs = get_effective_services(self.user)
        self.assertIn('notes', slugs)

    def test_unapproved_tool_absent_from_effective(self):
        """Tool not in enabled_tools (pending/denied request) not in effective set."""
        # Give user base tools but NOT notes
        self.profile.enabled_tools.set(Tool.objects.filter(slug__in=['id', 'hive']))
        ServiceAccessRequest.objects.create(
            user=self.user, tool=Tool.objects.get(slug='notes'), status='pending',
        )
        slugs = get_effective_services(self.user)
        self.assertNotIn('notes', slugs)

    def test_denied_request_absent_from_effective(self):
        """Denied request: tool not added to enabled_tools, so absent."""
        self.profile.enabled_tools.set(Tool.objects.filter(slug__in=['id', 'hive']))
        ServiceAccessRequest.objects.create(
            user=self.user, tool=Tool.objects.get(slug='notes'), status='denied',
        )
        slugs = get_effective_services(self.user)
        self.assertNotIn('notes', slugs)

    def test_revoked_grant_absent_from_effective(self):
        """Revoked grant: tool removed from enabled_tools disappears from effective set."""
        notes_tool = Tool.objects.get(slug='notes')
        self.profile.enabled_tools.add(notes_tool)
        self.assertIn('notes', get_effective_services(self.user))
        # Revoke
        self.profile.enabled_tools.remove(notes_tool)
        self.assertNotIn('notes', get_effective_services(self.user))

    def test_staff_user_gets_all_active_services(self):
        """Staff user effective set == all active tools regardless of M2M."""
        self.user.is_staff = True
        self.user.save()
        self.profile.enabled_tools.clear()  # M2M is empty
        active_slugs = set(Tool.objects.filter(is_active=True).values_list('slug', flat=True))
        self.assertEqual(set(get_effective_services(self.user)), active_slugs)

    def test_inactive_tool_excluded(self):
        """Inactive tools are never in the effective set, even if in enabled_tools."""
        inactive = _make_tool('legacy-tool', active=False)
        self.profile.enabled_tools.add(inactive)
        slugs = get_effective_services(self.user)
        self.assertNotIn('legacy-tool', slugs)


class TokenConsistencyTests(TestCase):
    """Token claims must equal get_effective_services output (INV-5)."""

    def setUp(self):
        self.user = User.objects.create_user(
            username='bob', email='bob@test.com', password='pw'
        )
        self.profile, _ = UserProfile.objects.get_or_create(user=self.user)
        _make_tool('id', is_default_enabled=True)
        _make_tool('hive', is_default_enabled=True)
        _make_tool('notes', requires_approval=True)
        self.profile.enabled_tools.set(Tool.objects.filter(slug__in=['id', 'hive']))

    def test_token_enabled_services_matches_get_effective_services(self):
        """Token enabled_services == get_effective_services() (INV-5 triangle check)."""
        canonical = set(get_effective_services(self.user))
        tokens = get_tokens_for_user(self.user)
        claims = _decode_token(tokens['access'])
        self.assertEqual(set(claims['enabled_services']), canonical)

    def test_token_excludes_unapproved_service(self):
        """A service not in enabled_tools is absent from the token claim."""
        tokens = get_tokens_for_user(self.user)
        claims = _decode_token(tokens['access'])
        self.assertNotIn('notes', claims['enabled_services'])

    def test_token_includes_approved_service(self):
        """Approving a service updates enabled_tools → appears in next token."""
        notes_tool = Tool.objects.get(slug='notes')
        self.profile.enabled_tools.add(notes_tool)
        tokens = get_tokens_for_user(self.user)
        claims = _decode_token(tokens['access'])
        self.assertIn('notes', claims['enabled_services'])

    def test_token_refresh_picks_up_revocation(self):
        """Token refresh re-reads live state (INV-5): revoked service drops off."""
        from identity.views import _ClaimRefreshingTokenRefreshSerializer
        notes_tool = Tool.objects.get(slug='notes')
        self.profile.enabled_tools.add(notes_tool)
        tokens = get_tokens_for_user(self.user)
        # Verify notes is in access token before revocation
        claims_before = _decode_token(tokens['access'])
        self.assertIn('notes', claims_before['enabled_services'])

        # Revoke the grant
        self.profile.enabled_tools.remove(notes_tool)

        # Refresh
        serializer = _ClaimRefreshingTokenRefreshSerializer(
            data={'refresh': tokens['refresh']}
        )
        serializer.is_valid(raise_exception=True)
        new_access = serializer.validated_data['access']
        claims_after = _decode_token(new_access)
        # Revocation must have propagated
        self.assertNotIn('notes', claims_after['enabled_services'])


class AdminReportConsistencyTests(TestCase):
    """AdminUserServicesView must report the same effective set as token claims (INV-5)."""

    def setUp(self):
        self.admin_user = User.objects.create_superuser(
            username='admin', email='admin@test.com', password='pw'
        )
        self.regular_user = User.objects.create_user(
            username='carol', email='carol@test.com', password='pw'
        )
        self.profile, _ = UserProfile.objects.get_or_create(user=self.regular_user)
        _make_tool('id', is_default_enabled=True)
        _make_tool('hive', is_default_enabled=True)
        _make_tool('notes', requires_approval=True)
        self.profile.enabled_tools.set(Tool.objects.filter(slug__in=['id', 'hive', 'notes']))
        self.client = APIClient()
        self.client.force_authenticate(user=self.admin_user)

    def test_admin_report_matches_get_effective_services(self):
        """Admin report enabled_services == get_effective_services() for regular user."""
        canonical = set(get_effective_services(self.regular_user))
        resp = self.client.get(f'/api/auth/admin/users/{self.regular_user.id}/services/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(set(resp.data['enabled_services']), canonical)

    def test_admin_report_matches_token_for_regular_user(self):
        """Admin report == token claim for regular user (full INV-5 triangle)."""
        tokens = get_tokens_for_user(self.regular_user)
        token_slugs = set(_decode_token(tokens['access'])['enabled_services'])
        resp = self.client.get(f'/api/auth/admin/users/{self.regular_user.id}/services/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(set(resp.data['enabled_services']), token_slugs)

    def test_staff_user_admin_report_includes_all_services(self):
        """Staff user admin report lists all active services (staff-all path)."""
        self.regular_user.is_staff = True
        self.regular_user.save()
        active_slugs = set(Tool.objects.filter(is_active=True).values_list('slug', flat=True))
        resp = self.client.get(f'/api/auth/admin/users/{self.regular_user.id}/services/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(set(resp.data['enabled_services']), active_slugs)
        self.assertTrue(resp.data['is_staff'])

    def test_admin_report_shows_revocation(self):
        """Admin report reflects revoked grant (removed from enabled_tools)."""
        notes_tool = Tool.objects.get(slug='notes')
        self.assertIn('notes', get_effective_services(self.regular_user))
        self.profile.enabled_tools.remove(notes_tool)
        resp = self.client.get(f'/api/auth/admin/users/{self.regular_user.id}/services/')
        self.assertNotIn('notes', resp.data['enabled_services'])


class DownstreamEnforcementContractTests(TestCase):
    """Contract tests proving the claim content correctly gates downstream enforcement.

    ID is the issuer, not the enforcer. These tests verify the *contract*:
    the enabled_services claim in the token correctly reflects grant state,
    so any downstream service checking that claim will make the right decision.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username='dave', email='dave@test.com', password='pw'
        )
        self.profile, _ = UserProfile.objects.get_or_create(user=self.user)
        _make_tool('id', is_default_enabled=True)
        _make_tool('hive', is_default_enabled=True)
        _make_tool('notes', requires_approval=True)
        # user has only base tools
        self.profile.enabled_tools.set(Tool.objects.filter(slug__in=['id', 'hive']))

    def test_missing_grant_absent_from_claim_contract(self):
        """Service absent from approved grants is absent from enabled_services claim.

        Downstream enforcement: `if 'notes' not in request.auth['enabled_services']
        → 403` would correctly deny this user.
        """
        tokens = get_tokens_for_user(self.user)
        claims = _decode_token(tokens['access'])
        # Contract assertion: notes is not in claim → downstream correctly denies
        self.assertNotIn('notes', claims['enabled_services'],
            "notes must be absent from enabled_services when user has no approved grant")

    def test_present_grant_in_claim_contract(self):
        """Approved grant is present in enabled_services claim.

        Downstream enforcement: `if 'notes' in request.auth['enabled_services']
        → allow` would correctly permit this user.
        """
        self.profile.enabled_tools.add(Tool.objects.get(slug='notes'))
        tokens = get_tokens_for_user(self.user)
        claims = _decode_token(tokens['access'])
        # Contract assertion: notes is in claim → downstream correctly allows
        self.assertIn('notes', claims['enabled_services'],
            "notes must be present in enabled_services when user has an approved grant")

    def test_superuser_claim_contains_all_active_services(self):
        """Superuser token carries all active services — staff-all path contract."""
        self.user.is_superuser = True
        self.user.save()
        active_slugs = set(Tool.objects.filter(is_active=True).values_list('slug', flat=True))
        tokens = get_tokens_for_user(self.user)
        claims = _decode_token(tokens['access'])
        self.assertEqual(set(claims['enabled_services']), active_slugs,
            "Superuser enabled_services must equal all active tools")
