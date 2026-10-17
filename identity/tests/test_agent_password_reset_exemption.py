"""PLAT-556: agent/service accounts are exempt from human password-reset paths.

The 2026-06-16 outage: a platform-wide password change reset agent shizuha-id
account passwords away from the baked-in container ``AGENT_PASSWORD`` → the fleet
401'd at login and idled. The stopgap blocks agent accounts from the human reset
paths (admin reset + forgot-password) so a human-security sweep can't desync an
agent's credential. Pure-logic test (no DB) over the ``_reject_agent_password_reset``
guard — same SimpleNamespace style as ``test_k8s_agent_attestation``.
"""
from types import SimpleNamespace

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from rest_framework import status

from identity.models import Tool
from identity.services import get_default_new_user_service_slugs
from identity.views import _is_agent_user, _reject_agent_password_reset


def _user(account_type=None, *, has_profile=True, email="acct@example.com"):
    profile = SimpleNamespace(account_type=account_type) if has_profile else None
    return SimpleNamespace(username="acct", profile=profile, email=email)


class AgentPasswordResetExemptionTests(SimpleTestCase):
    def test_agent_account_reset_blocked_with_409(self):
        resp = _reject_agent_password_reset(_user("agent"))
        self.assertIsNotNone(resp, "agent reset must be short-circuited")
        self.assertEqual(resp.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(resp.data["error"], "agent_service_account")

    def test_human_account_reset_allowed(self):
        self.assertIsNone(_reject_agent_password_reset(_user("human")))

    def test_agent_provisioning_optin_allowed(self):
        # The deliberate single-write provisioning / self-heal path opts in and
        # is the legitimate writer of an agent's password — must NOT be blocked,
        # else first-time provisioning + drift self-heal break (they call the
        # same admin set-password endpoint).
        self.assertIsNone(
            _reject_agent_password_reset(_user("agent"), is_provisioning=True))

    def test_missing_profile_treated_as_human(self):
        # Safe default: no profile → not an agent → reset proceeds for humans.
        self.assertIsNone(_reject_agent_password_reset(_user(has_profile=False)))

    def test_is_agent_user_classification(self):
        self.assertTrue(_is_agent_user(_user("agent")))
        self.assertFalse(_is_agent_user(_user("human")))
        self.assertFalse(_is_agent_user(_user(has_profile=False)))

    # PLAT-671: the @agents.shizuha.io email domain ALSO classifies an agent —
    # defense-in-depth so an agent account missing account_type='agent' is still
    # protected from human password/2FA sweeps.
    def test_agent_classified_by_email_domain_without_account_type(self):
        # No profile / no account_type, but an agent service-account email.
        self.assertTrue(_is_agent_user(_user(has_profile=False, email="kai@agents.shizuha.io")))
        # Even if account_type was mistakenly set to human, the domain is authoritative.
        self.assertTrue(_is_agent_user(_user("human", email="rin@agents.shizuha.io")))

    def test_agent_email_domain_match_is_case_insensitive(self):
        self.assertTrue(_is_agent_user(_user(has_profile=False, email="Kai@Agents.Shizuha.IO")))

    def test_non_agent_domain_is_human(self):
        self.assertFalse(_is_agent_user(_user(has_profile=False, email="someone@example.com")))
        # substring that is not the actual domain must not match
        self.assertFalse(_is_agent_user(_user(has_profile=False, email="evil@notagents.shizuha.io.attacker.com")))

    def test_email_domain_agent_reset_blocked_with_409(self):
        # The end-to-end guard: an @agents.shizuha.io account with NO account_type
        # is still short-circuited from a human reset (the gap PLAT-671 closes).
        resp = _reject_agent_password_reset(_user(has_profile=False, email="nori@agents.shizuha.io"))
        self.assertIsNotNone(resp)
        self.assertEqual(resp.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(resp.data["error"], "agent_service_account")

    @override_settings(AGENT_ACCOUNT_EMAIL_DOMAIN="agents.example.test")
    def test_agent_email_domain_is_configurable(self):
        self.assertTrue(_is_agent_user(_user(has_profile=False, email="x@agents.example.test")))
        self.assertFalse(_is_agent_user(_user(has_profile=False, email="x@agents.shizuha.io")))


# PLAT-496 / SEC-5: new human users get Account + HIVE only by default.
class LeastPrivilegeNewUserDefaultsTests(TestCase):
    def setUp(self):
        Tool.objects.update_or_create(
            slug='id',
            defaults={
                'display_name': 'Account', 'is_active': True,
                'is_default_enabled': True, 'requires_approval': False,
                'requires_superuser': False,
            },
        )
        Tool.objects.update_or_create(
            slug='hive',
            defaults={
                'display_name': 'Hive', 'is_active': True,
                'is_default_enabled': True, 'requires_approval': False,
                'requires_superuser': False,
            },
        )
        # Simulate future catalog drift: even if another service is accidentally
        # default-enabled and does not require approval, runtime default grants must
        # still stay pinned to the explicitly managed universal defaults.
        Tool.objects.update_or_create(
            slug='pulse',
            defaults={
                'display_name': 'Pulse', 'is_active': True,
                'is_default_enabled': True, 'requires_approval': False,
                'requires_superuser': False,
            },
        )

    def test_default_helper_ignores_broad_catalog_flags(self):
        self.assertEqual(
            set(get_default_new_user_service_slugs()),
            {'id', 'hive', 'mail'},
        )

    def test_created_user_profile_gets_universal_defaults(self):
        user = get_user_model().objects.create_user(
            username='plat496-user',
            email='plat496@example.com',
            password='irrelevant-test-password',
        )

        self.assertEqual(
            set(user.profile.enabled_tools.values_list('slug', flat=True)),
            {'id', 'hive', 'mail'},
        )


@override_settings(FLEET_PROVISIONER_TOKEN='test-fleet-token')
class FleetProvisionerEndpointTests(TestCase):
    def test_scoped_endpoint_creates_approved_agent_and_sets_password(self):
        response = self.client.post(
            '/api/internal/fleet/provision-agent/',
            data={
                'username': 'kai',
                'email': 'kai@agents.shizuha.io',
                'password': 'generated-password!A1',
                'display_name': 'Kai Engineer',
                'runtime_id': 'hive-fleet',
            },
            content_type='application/json',
            HTTP_X_FLEET_PROVISIONER_TOKEN='test-fleet-token',
            **{'wsgi.url_scheme': 'http'},
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        user = get_user_model().objects.get(username='kai')
        self.assertTrue(user.check_password('generated-password!A1'))
        self.assertTrue(user.is_active)
        self.assertEqual(user.profile.account_type, 'agent')
        self.assertEqual(user.profile.approval_status, 'approved')
        self.assertEqual(user.profile.agent_runtime_id, 'hive-fleet')

    def test_scoped_endpoint_rejects_human_namespace_and_missing_token(self):
        missing = self.client.post(
            '/api/internal/fleet/provision-agent/',
            data={'username': 'kai', 'email': 'kai@agents.shizuha.io', 'password': 'generated-password!A1'},
            content_type='application/json',
        )
        self.assertEqual(missing.status_code, status.HTTP_403_FORBIDDEN)

        wrong_domain = self.client.post(
            '/api/internal/fleet/provision-agent/',
            data={'username': 'hritik', 'email': 'test-owner@example.com', 'password': 'generated-password!A1'},
            content_type='application/json',
            HTTP_X_FLEET_PROVISIONER_TOKEN='test-fleet-token',
        )
        self.assertEqual(wrong_domain.status_code, status.HTTP_403_FORBIDDEN)

    def test_scoped_endpoint_cannot_take_over_existing_human_username(self):
        get_user_model().objects.create_user(
            username='human',
            email='human@example.com',
            password='human-password!A1',
        )
        response = self.client.post(
            '/api/internal/fleet/provision-agent/',
            data={'username': 'human', 'email': 'human@agents.shizuha.io', 'password': 'generated-password!A1'},
            content_type='application/json',
            HTTP_X_FLEET_PROVISIONER_TOKEN='test-fleet-token',
        )
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(response.json()['reason'], 'username_taken_by_human')
