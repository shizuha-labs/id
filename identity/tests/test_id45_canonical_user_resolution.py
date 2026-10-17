"""ID-45 canonical user resolution contract tests."""
import importlib.util
import os
import sys
from pathlib import Path

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIRequestFactory, force_authenticate

from identity.internal_urls import (
    InternalUserByEmailView,
    InternalUserByUsernameView,
    InternalUserView,
)
from identity.models import UserProfile
from identity.views import ProfileView, UserView

User = get_user_model()


class CanonicalUserResolutionContractTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = User.objects.create_user(
            username='CanonicalUser',
            email='Person@Example.COM',
            password='pw',
            first_name='Canon',
            last_name='Person',
            is_active=True,
        )
        self.profile, _ = UserProfile.objects.get_or_create(user=self.user)
        self.profile.approval_status = 'approved'
        self.profile.lifecycle_state = 'active'
        self.profile.account_type = 'human'
        self.profile.timezone = 'Asia/Kolkata'
        self.profile.save(update_fields=['approval_status', 'lifecycle_state', 'account_type', 'timezone', 'updated_at'])

    def _auth_get(self, view_cls, path):
        request = self.factory.get(path)
        force_authenticate(request, user=self.user)
        return view_cls.as_view()(request)

    def _assert_canonical_user(self, data):
        self.assertEqual(data['id'], self.user.id)
        self.assertEqual(data['email'], self.user.email)
        self.assertEqual(data['username'], self.user.username)
        self.assertEqual(data['display_name'], 'Canon Person')
        self.assertEqual(data['approval_status'], 'approved')
        self.assertEqual(data['lifecycle_state'], 'active')
        self.assertEqual(data['account_type'], 'human')
        self.assertEqual(data['profile']['user_id'], self.user.id)
        self.assertEqual(data['profile']['email'], self.user.email)
        self.assertEqual(data['profile']['username'], self.user.username)
        self.assertEqual(data['profile']['lifecycle_state'], 'active')

    def test_id_email_username_and_current_user_resolve_same_canonical_record(self):
        current = self._auth_get(UserView, '/id/api/auth/user/')
        by_id = InternalUserView.as_view()(self.factory.get('/internal/users/'), user_id=self.user.id)
        by_email = InternalUserByEmailView.as_view()(
            self.factory.get('/internal/users/by-email/', {'email': ' person@example.com '})
        )
        by_username = InternalUserByUsernameView.as_view()(
            self.factory.get('/internal/users/by-username/', {'username': 'canonicaluser'})
        )

        for response in (current, by_id, by_email, by_username):
            self.assertEqual(response.status_code, 200)
            self._assert_canonical_user(response.data)

    def test_profile_endpoint_carries_same_canonical_identity_fields(self):
        response = self._auth_get(ProfileView, '/id/api/auth/profile/')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['user_id'], self.user.id)
        self.assertEqual(response.data['email'], self.user.email)
        self.assertEqual(response.data['username'], self.user.username)
        self.assertEqual(response.data['first_name'], self.user.first_name)
        self.assertEqual(response.data['last_name'], self.user.last_name)
        self.assertEqual(response.data['is_active'], self.user.is_active)
        self.assertEqual(response.data['lifecycle_state'], 'active')
        self.assertEqual(response.data['timezone'], 'Asia/Kolkata')

    def test_missing_and_deactivated_lookup_behaviour_is_explicit(self):
        missing = InternalUserByEmailView.as_view()(
            self.factory.get('/internal/users/by-email/', {'email': 'missing@example.com'})
        )
        blank = InternalUserByEmailView.as_view()(
            self.factory.get('/internal/users/by-email/', {'email': '   '})
        )
        self.user.is_active = False
        self.user.save(update_fields=['is_active'])
        self.profile.lifecycle_state = 'deactivated'
        self.profile.save(update_fields=['lifecycle_state', 'updated_at'])
        hidden = InternalUserByEmailView.as_view()(
            self.factory.get('/internal/users/by-email/', {'email': 'person@example.com'})
        )

        self.assertEqual(missing.status_code, 404)
        self.assertEqual(missing.data['error'], 'User not found')
        self.assertEqual(blank.status_code, 400)
        self.assertEqual(blank.data['error'], 'Email parameter is required')
        self.assertEqual(hidden.status_code, 200)
        self.assertFalse(hidden.data['is_active'])
        self.assertEqual(hidden.data['lifecycle_state'], 'deactivated')
        self.assertEqual(hidden.data['profile']['lifecycle_state'], 'deactivated')


class McpIdentityFallbackContractTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        repo_root = Path(__file__).resolve().parents[2]
        mcp_dir = repo_root / 'mcp-server'
        sys.path.insert(0, str(mcp_dir))
        os.environ.setdefault('SHIZUHA_ID_URL', 'http://id.test')
        os.environ.setdefault('SHIZUHA_ID_JWT_TOKEN', 'test-token')
        spec = importlib.util.spec_from_file_location('id45_id_server_under_test', mcp_dir / 'id_server.py')
        cls.id_server = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.id_server)

    def _call_get_my_identity(self, api_result):
        class FakeBase:
            def api_request(self, *args, **kwargs):
                return api_result

            def get_identity(self):
                return {
                    'user_id': 99,
                    'email': 'stale-jwt@example.test',
                    'username': 'stale-jwt',
                }

            def format_error(self, result):
                return f"# Error (HTTP {result.get('status_code', 'unknown')})\n\n**Message**: {result['error']}"

        original_base = self.id_server.base
        try:
            self.id_server.base = FakeBase()
            return self.id_server.get_my_identity()
        finally:
            self.id_server.base = original_base

    def test_mcp_my_identity_does_not_fallback_to_unsigned_jwt_on_auth_error(self):
        output = self._call_get_my_identity({
            'error': '401 Client Error: Unauthorized for url',
            'detail': {'detail': 'Token is inactive or expired'},
            'status_code': 401,
        })

        self.assertIn('HTTP 401', output)
        self.assertIn('Unauthorized', output)
        self.assertNotIn('stale-jwt@example.test', output)

    def test_mcp_my_identity_keeps_jwt_fallback_for_unavailable_api(self):
        output = self._call_get_my_identity({
            'error': 'Connection aborted',
        })

        self.assertIn('stale-jwt@example.test', output)
        self.assertIn('stale-jwt', output)
