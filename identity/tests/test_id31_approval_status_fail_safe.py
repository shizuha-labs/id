"""ID-31: UserProfile.approval_status fail-safe default.

Regression tests covering the four acceptance criteria:
1. Generic profile/create path defaults to pending (model default is no longer 'approved').
2. Registration flow remains pending.
3. Internal agent provisioning remains approved+active.
4. Non-staff public approve/deny endpoint remains forbidden.

Uses SimpleNamespace for unit-level checks (no DB) and Django TestCase for DB paths.
"""
from types import SimpleNamespace
from unittest.mock import patch

from django.test import TestCase, SimpleTestCase, override_settings
from django.contrib.auth import get_user_model

User = get_user_model()
_projection_patcher = None


def setUpModule():
    global _projection_patcher
    _projection_patcher = patch(
        'identity.views._fetch_membership_projection',
        return_value=({}, [], {}),
    )
    _projection_patcher.start()


def tearDownModule():
    _projection_patcher.stop()


# ---------------------------------------------------------------------------
# Unit-level: model field default (no DB required)
# ---------------------------------------------------------------------------

class ApprovalStatusDefaultTests(SimpleTestCase):
    """Verify the model-level default changed to 'pending' (ID-31)."""

    def test_approval_status_model_default_is_pending(self):
        from identity.models import UserProfile
        field = UserProfile._meta.get_field('approval_status')
        self.assertEqual(field.default, 'pending',
                         "approval_status default must be 'pending' (fail-safe) after ID-31")

    def test_approval_status_model_default_is_not_approved(self):
        from identity.models import UserProfile
        field = UserProfile._meta.get_field('approval_status')
        self.assertNotEqual(field.default, 'approved',
                            "approval_status must no longer default to 'approved' (ID-31)")


# ---------------------------------------------------------------------------
# DB-level: end-to-end profile creation via signal
# ---------------------------------------------------------------------------

class ProfileSignalDefaultTests(TestCase):
    """New User creation via signal must produce a profile with approval_status='pending'."""

    def test_new_user_signal_creates_pending_profile(self):
        from identity.models import UserProfile
        user = User.objects.create_user(
            username='testuser_id31_signal',
            email='testuser_id31_signal@example.com',
            password='TestPass123!',
        )
        profile = UserProfile.objects.get(user=user)
        self.assertEqual(profile.approval_status, 'pending',
                         "Signal-created profile must be 'pending' by default (ID-31)")

    def test_new_staff_user_signal_creates_pending_profile(self):
        """Staff users created directly are also pending — explicit approval required."""
        from identity.models import UserProfile
        user = User.objects.create_user(
            username='teststaff_id31',
            email='teststaff_id31@example.com',
            password='TestPass123!',
            is_staff=True,
        )
        profile = UserProfile.objects.get(user=user)
        self.assertEqual(profile.approval_status, 'pending')


# ---------------------------------------------------------------------------
# Internal creation paths must remain approved
# ---------------------------------------------------------------------------

class InternalUserCreateViewTests(TestCase):
    """InternalUserCreateView must explicitly approve created users (ID-31)."""

    def test_internal_user_create_sets_approved(self):
        from identity.models import UserProfile
        from django.test import RequestFactory
        from identity.internal_urls import InternalUserCreateView

        factory = RequestFactory()
        request = factory.post('/internal/users/', {
            'username': 'internaluser_id31',
            'email': 'internaluser_id31@example.com',
            'password': 'InternalPass123!',
        }, content_type='application/json')
        import json
        request.data = {
            'username': 'internaluser_id31',
            'email': 'internaluser_id31@example.com',
            'password': 'InternalPass123!',
        }
        view = InternalUserCreateView.as_view()
        response = view(request)
        self.assertEqual(response.status_code, 201)
        user = User.objects.get(username='internaluser_id31')
        profile = UserProfile.objects.get(user=user)
        self.assertEqual(profile.approval_status, 'approved',
                         "InternalUserCreateView must produce approval_status='approved' (ID-31)")


class AgentCreateViewTests(TestCase):
    """The current scoped Hive fleet route provisions approved active agents."""

    def test_agent_provision_remains_approved(self):
        import secrets
        from identity.models import UserProfile
        from rest_framework.test import APIClient
        token = secrets.token_urlsafe(32)
        client = APIClient()
        path = '/api/internal/fleet/provision-agent/'
        payload = {
            'username': 'testagent_id31',
            'email': 'testagent_id31@agents.shizuha.io',
            'password': 'Agent-Fixture-Strong-Password-73!',
            'runtime_id': 'id31-fixture-runtime',
        }
        with override_settings(FLEET_PROVISIONER_TOKEN=token):
            for headers in ({}, {'HTTP_X_FLEET_PROVISIONER_TOKEN': 'incorrect-fixture-token'}):
                self.assertEqual(client.post(path, payload, format='json', **headers).status_code, 403)
                self.assertFalse(User.objects.filter(username=payload['username']).exists())
            response = client.post(path, payload, format='json', HTTP_X_FLEET_PROVISIONER_TOKEN=token)
        self.assertEqual(response.status_code, 201)
        user = User.objects.get(username='testagent_id31')
        profile = UserProfile.objects.get(user=user)
        self.assertEqual(profile.approval_status, 'approved',
                         "Agent provisioning must remain approved after ID-31")
        self.assertTrue(user.is_active)
        self.assertEqual(profile.lifecycle_state, 'active')
        self.assertEqual(profile.account_type, 'agent')
        self.assertEqual(profile.agent_runtime_id, payload['runtime_id'])


# ---------------------------------------------------------------------------
# Registration flow: must remain pending
# ---------------------------------------------------------------------------

class RegistrationApprovalTests(TestCase):
    """Registration paths must continue to set approval_status='pending'."""

    def test_adapters_registration_sets_pending(self):
        """The allauth adapter sets pending on social/registration sign-up."""
        from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
        from django.conf import settings
        from django.utils.module_loading import import_string
        from identity.models import UserProfile

        user = User.objects.create_user(username='reguser_id31',
                                        email='reguser_id31@example.test', is_active=True)
        UserProfile.objects.filter(user=user).update(approval_status='approved')
        adapter = import_string(settings.SOCIALACCOUNT_ADAPTER)()
        sociallogin = SimpleNamespace(user=user)
        # Only the external allauth save is isolated; exercise the configured
        # adapter's real pending/inactive writes against a previously active user.
        with patch.object(DefaultSocialAccountAdapter, 'save_user', return_value=user) as save:
            saved = adapter.save_user(None, sociallogin)
        save.assert_called_once_with(None, sociallogin, None)
        self.assertEqual(saved.pk, user.pk)
        user.refresh_from_db()
        self.assertFalse(user.is_active)
        self.assertEqual(UserProfile.objects.get(user=user).approval_status, 'pending')

    @override_settings(ALLOW_OPEN_REGISTRATION=False, TURNSTILE_REQUIRED=False,
                       SIGNUP_RATE_LIMITS_ENABLED=False)
    def test_register_api_sets_pending(self):
        """Public registration endpoint creates user with is_active=False + pending."""
        from identity.models import UserProfile

        response = self.client.post('/api/auth/register/', {
            'username': 'publicreg_id31',
            'email': 'publicreg_id31@example.com',
            'password': 'PublicReg123!',
            'password2': 'PublicReg123!',
            'first_name': 'Test',
            'last_name': 'User',
        }, content_type='application/json')

        self.assertEqual(response.status_code, 201)
        user = User.objects.get(username='publicreg_id31')
        profile = UserProfile.objects.get(user=user)
        self.assertEqual(profile.approval_status, 'pending')
        self.assertEqual(profile.lifecycle_state, 'pending')
        self.assertFalse(user.is_active)


# ---------------------------------------------------------------------------
# Non-staff approve/deny is forbidden (regression for ID-24 gate)
# ---------------------------------------------------------------------------

class ApprovalGateForbiddenTests(TestCase):
    """Non-staff users cannot approve/deny accounts (ID-24 regression)."""

    def setUp(self):
        self.approver = User.objects.create_user(
            username='nonadmin_id31',
            email='nonadmin_id31@example.com',
            password='NonAdmin123!',
            is_active=True,
        )
        from identity.models import UserProfile
        UserProfile.objects.filter(user=self.approver).update(approval_status='approved')
        self.target = User.objects.create_user(
            username='pendinguser_id31',
            email='pendinguser_id31@example.com',
            password='Pending123!',
            is_active=False,
        )

    def test_non_staff_cannot_approve(self):
        login_resp = self.client.post('/api/auth/login/', {
            'username': 'nonadmin_id31',
            'password': 'NonAdmin123!',
        }, content_type='application/json')
        self.assertEqual(login_resp.status_code, 200)

        token = login_resp.data['tokens']['access']
        approve_resp = self.client.post(
            f'/api/auth/admin/users/{self.target.id}/approve/',
            {'status': 'approved'},
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
        )
        self.assertEqual(approve_resp.status_code, 403)
        self.target.refresh_from_db()
        self.assertFalse(self.target.is_active)
        self.assertEqual(self.target.profile.approval_status, 'pending')
