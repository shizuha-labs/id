"""ID-56: deny-by-default wiring for the login/register/password-change views.

Unit-level (DB-free) coverage of the feature flag and the
``_reject_or_log_unknown_input`` gate, plus endpoint-level tests that verify
the three views reject unknown keys with 400 under the default enforce mode.
"""
import os
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from rest_framework import status

os.environ.setdefault('SHIZUHA_OAUTH_KEY_DIR', '/tmp/shizuha-id56-oauth-keys')

from identity.views import _strict_input_enforced, _reject_or_log_unknown_input
from identity.serializers import (
    LoginSerializer,
    RegisterSerializer,
    PasswordChangeSerializer,
)

LOGIN_URL = '/api/auth/login/'
REGISTER_URL = '/api/auth/register/'
PASSWORD_CHANGE_URL = '/api/auth/password/change/'


class Id56FlagTests(SimpleTestCase):
    def test_default_is_enforce(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('ID_STRICT_INPUT_ENFORCE', None)
            self.assertTrue(
                _strict_input_enforced(),
                'auth-view strict input must DEFAULT to enforce (kai compat audit cleared risk)',
            )

    def test_enforce_values(self):
        for v in ('1', 'true', 'on', 'enforce'):
            with patch.dict(os.environ, {'ID_STRICT_INPUT_ENFORCE': v}):
                self.assertTrue(_strict_input_enforced(), f'{v!r} must enforce')

    def test_shadow_values(self):
        for v in ('shadow', 'shadow-only', 'off', '0', 'false', 'disabled'):
            with patch.dict(os.environ, {'ID_STRICT_INPUT_ENFORCE': v}):
                self.assertFalse(_strict_input_enforced(), f'{v!r} must not enforce')


class Id56GateTests(SimpleTestCase):
    def _req(self, data):
        return SimpleNamespace(data=data)

    @patch.dict(os.environ, {'ID_STRICT_INPUT_ENFORCE': '1'})
    def test_enforce_rejects_unknown_field_login(self):
        resp = _reject_or_log_unknown_input(
            self._req({'username': 'a', 'password': 'b', 'evil': 1}),
            LoginSerializer, 'LoginView')
        self.assertIsNotNone(resp)
        self.assertEqual(resp.status_code, 400)
        self.assertIn('evil', resp.data)

    @patch.dict(os.environ, {'ID_STRICT_INPUT_ENFORCE': '1'})
    def test_enforce_allows_declared_fields(self):
        self.assertIsNone(_reject_or_log_unknown_input(
            self._req({'username': 'a', 'password': 'b'}), LoginSerializer, 'LoginView'))
        self.assertIsNone(_reject_or_log_unknown_input(
            self._req({'username': 'a', 'email': 'a@b.c', 'password': 'x',
                       'password2': 'x', 'first_name': 'A', 'last_name': 'B',
                       'captcha_token': 'tok', 'website': ''}),
            RegisterSerializer, 'RegisterView'))
        self.assertIsNone(_reject_or_log_unknown_input(
            self._req({'old_password': 'a', 'new_password': 'b', 'new_password2': 'b'}),
            PasswordChangeSerializer, 'PasswordChangeView'))

    def test_shadow_logs_but_does_not_reject(self):
        # The core safety property: in shadow (default), an unknown key is LOGGED
        # for the compat bake but NEVER 400'd — login/register/password behave
        # exactly as today.
        with patch.dict(os.environ, {'ID_STRICT_INPUT_ENFORCE': 'shadow'}):
            with self.assertLogs('identity.views', level='WARNING') as cm:
                resp = _reject_or_log_unknown_input(
                    self._req({'username': 'a', 'password': 'b', 'evil': 1}),
                    LoginSerializer, 'LoginView')
        self.assertIsNone(resp)
        joined = '\n'.join(cm.output)
        self.assertIn('ID-56 shadow', joined)
        self.assertIn('evil', joined)
        self.assertIn('LoginView', joined)

    @patch.dict(os.environ, {'ID_STRICT_INPUT_ENFORCE': '1'})
    def test_register_intent_field_accepted_under_enforce(self):
        # kai's compat audit: RegisterView reads request.data.get('intent') for
        # the Drive self-registration gate; it's now DECLARED, so even under
        # enforce it must NOT be rejected (else drive-register 400s).
        self.assertIsNone(_reject_or_log_unknown_input(
            self._req({'username': 'a', 'email': 'a@b.c', 'password': 'x',
                       'password2': 'x', 'intent': 'drive'}),
            RegisterSerializer, 'RegisterView'))

    @patch.dict(os.environ, {'ID_STRICT_INPUT_ENFORCE': '1'})
    def test_non_dict_data_is_ignored(self):
        self.assertIsNone(_reject_or_log_unknown_input(
            self._req(['not', 'a', 'dict']), LoginSerializer, 'LoginView'))
        self.assertIsNone(_reject_or_log_unknown_input(
            SimpleNamespace(), LoginSerializer, 'LoginView'))


class Id56EndpointTests(TestCase):
    """Endpoint-level tests: the three auth views reject unknown keys with 400
    under the default enforce mode. The strict gate fires before authentication
    for login/register (AllowAny); password-change needs an authenticated user."""

    @classmethod
    def setUpTestData(cls):
        User = get_user_model()
        cls.user = User.objects.create_user(
            username='pwtest',
            password='Str0ng!Pass-56',
        )

    def _auth_client(self):
        self.client.force_login(self.user)
        return self.client

    def test_login_rejects_unknown_field(self):
        resp = self.client.post(
            LOGIN_URL,
            {'username': 'a', 'password': 'b', 'evil': 1},
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('evil', resp.json())

    def test_login_allows_declared_fields(self):
        # Strict gate passes; view then fails on auth (no such user) — that's fine.
        resp = self.client.post(
            LOGIN_URL,
            {'username': 'nonexistent', 'password': 'hunter2'},
            content_type='application/json',
        )
        self.assertNotEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_rejects_unknown_field(self):
        resp = self.client.post(
            REGISTER_URL,
            {'username': 'a', 'email': 'a@b.c', 'password': 'x',
             'password2': 'x', 'evil': 1},
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('evil', resp.json())

    def test_register_allows_declared_fields_with_intent(self):
        # kai's compat audit: 'intent' is declared and must not be rejected.
        resp = self.client.post(
            REGISTER_URL,
            {'username': 'newuser', 'email': 'new@b.c', 'password': 'Str0ng!Pass',
             'password2': 'Str0ng!Pass', 'intent': 'drive'},
            content_type='application/json',
        )
        # Strict gate passes; view proceeds (may fail on other validation).
        self.assertNotEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_change_rejects_unknown_field(self):
        resp = self._auth_client().post(
            PASSWORD_CHANGE_URL,
            {'old_password': 'Str0ng!Pass-56', 'new_password': 'NewStr0ng!Pass',
             'new_password2': 'NewStr0ng!Pass', 'evil': 1},
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('evil', resp.json())

    def test_password_change_allows_declared_fields(self):
        resp = self._auth_client().post(
            PASSWORD_CHANGE_URL,
            {'old_password': 'Str0ng!Pass-56', 'new_password': 'NewStr0ng!Pass',
             'new_password2': 'NewStr0ng!Pass'},
            content_type='application/json',
        )
        self.assertNotEqual(resp.status_code, status.HTTP_400_BAD_REQUEST)
