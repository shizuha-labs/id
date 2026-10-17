import time
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from rest_framework import status
from rest_framework.test import APIClient, APIRequestFactory

from identity.models import PasswordResetToken
from identity.views import PasswordResetRequestView

User = get_user_model()
GENERIC = 'If an account exists with this email, you will receive a reset link.'
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


@override_settings(
    PASSWORD_RESET_MIN_RESPONSE_SECONDS=0.10,
    PASSWORD_RESET_MAX_ATTEMPTS=10,
    PASSWORD_RESET_WINDOW_SECONDS=300,
    PASSWORD_RESET_BASE_LOCKOUT_SECONDS=60,
    PASSWORD_RESET_MAX_LOCKOUT_SECONDS=300,
)
class PasswordResetNonEnumerationTests(TestCase):
    def setUp(self):
        cache.clear()
        self.factory = APIRequestFactory()
        self.view = PasswordResetRequestView.as_view()
        self.user = User.objects.create_user(
            username='reset-known', email='known@example.com', password='OldPassw0rd!'
        )

    def _post(self, email):
        request = self.factory.post(
            '/api/auth/password/reset/', {'email': email}, format='json', REMOTE_ADDR='203.0.113.10'
        )
        start = time.monotonic()
        response = self.view(request)
        return response, time.monotonic() - start

    @patch('identity.password_reset_security.send_password_reset_email_async')
    def test_reset_request_response_is_identical_and_padded_for_existing_and_unknown_email(self, send_reset):
        existing, existing_s = self._post('known@example.com')
        unknown, unknown_s = self._post('unknown@example.com')

        self.assertEqual(existing.status_code, status.HTTP_200_OK)
        self.assertEqual(unknown.status_code, status.HTTP_200_OK)
        self.assertEqual(existing.data, {'message': GENERIC})
        self.assertEqual(unknown.data, {'message': GENERIC})
        self.assertGreaterEqual(existing_s, 0.09)
        self.assertGreaterEqual(unknown_s, 0.09)
        self.assertLess(abs(existing_s - unknown_s), 0.075)
        self.assertEqual(send_reset.call_count, 1)
        self.assertEqual(PasswordResetToken.objects.filter(user=self.user).count(), 1)

    @patch('identity.password_reset_security.send_password_reset_email_async')
    def test_unknown_reset_request_does_not_send_account_creation_email(self, send_reset):
        response, _elapsed = self._post('nobody@example.com')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {'message': GENERIC})
        send_reset.assert_not_called()
        self.assertEqual(PasswordResetToken.objects.count(), 0)

    @patch('identity.password_reset_security.send_password_reset_email')
    def test_slow_reset_email_send_is_not_on_response_path(self, send_reset):
        def slow_send(_user, _reset_url):
            time.sleep(0.25)
            return True

        send_reset.side_effect = slow_send

        existing, existing_s = self._post('known@example.com')
        unknown, unknown_s = self._post('slow-unknown@example.com')

        self.assertEqual(existing.status_code, status.HTTP_200_OK)
        self.assertEqual(unknown.status_code, status.HTTP_200_OK)
        self.assertEqual(existing.data, {'message': GENERIC})
        self.assertEqual(unknown.data, {'message': GENERIC})
        self.assertLess(existing_s, 0.18)
        self.assertGreaterEqual(existing_s, 0.09)
        self.assertGreaterEqual(unknown_s, 0.09)
        self.assertLess(abs(existing_s - unknown_s), 0.075)


@override_settings(
    LOGIN_PASSWORD_MAX_ATTEMPTS=2,
    LOGIN_PASSWORD_WINDOW_SECONDS=300,
    LOGIN_PASSWORD_BASE_LOCKOUT_SECONDS=60,
    LOGIN_PASSWORD_MAX_LOCKOUT_SECONDS=300,
    PASSWORD_RESET_MIN_RESPONSE_SECONDS=0,
    PASSWORD_RESET_MAX_ATTEMPTS=2,
    PASSWORD_RESET_WINDOW_SECONDS=300,
    PASSWORD_RESET_BASE_LOCKOUT_SECONDS=60,
    PASSWORD_RESET_MAX_LOCKOUT_SECONDS=300,
    TWOFA_LOGIN_ENFORCEMENT='off',
)
class LoginAndResetBackoffTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = APIClient()
        User.objects.create_user(username='alice', email='alice@example.com', password='CorrectPassw0rd!')
        User.objects.create_user(username='bob', email='bob@example.com', password='CorrectPassw0rd!')

    def _login(self, username, ip, remote_addr=None):
        return self.client.post(
            '/api/auth/login/', {'username': username, 'password': 'wrong-password'},
            format='json', HTTP_X_FORWARDED_FOR=ip, REMOTE_ADDR=remote_addr or ip,
        )

    def test_login_per_account_lockout_survives_ip_rotation(self):
        first = self._login('alice', '198.51.100.1')
        self.assertEqual(first.status_code, status.HTTP_401_UNAUTHORIZED)

        second = self._login('alice', '198.51.100.2')
        self.assertEqual(second.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertEqual(second.data['error'], 'too_many_login_attempts')

    def test_login_username_and_email_share_account_lockout_budget(self):
        first = self._login('alice', '198.51.100.21')
        self.assertEqual(first.status_code, status.HTTP_401_UNAUTHORIZED)

        second = self._login('alice@example.com', '198.51.100.22')
        self.assertEqual(second.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertEqual(second.data['error'], 'too_many_login_attempts')

    def test_successful_login_clears_canonical_account_lockout_budget(self):
        first = self._login('alice', '198.51.100.31')
        self.assertEqual(first.status_code, status.HTTP_401_UNAUTHORIZED)

        success = self.client.post(
            '/api/auth/login/', {'username': 'alice@example.com', 'password': 'CorrectPassw0rd!'},
            format='json', HTTP_X_FORWARDED_FOR='198.51.100.32',
        )
        self.assertEqual(success.status_code, status.HTTP_200_OK)

        after_clear = self._login('alice@example.com', '198.51.100.33')
        self.assertEqual(after_clear.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_per_ip_lockout_catches_spray_across_accounts(self):
        first = self._login('alice', '198.51.100.9')
        self.assertEqual(first.status_code, status.HTTP_401_UNAUTHORIZED)

        second = self._login('bob', '198.51.100.9')
        self.assertEqual(second.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertEqual(second.data['error'], 'too_many_login_attempts')

    @override_settings(
        LOGIN_PASSWORD_IP_EXEMPT_CIDRS='100.64.0.3/32',
        LOGIN_PASSWORD_TRUSTED_PROXY_CIDRS='10.0.0.0/8,100.64.0.0/10',
    )
    def test_trusted_internal_login_ip_exemption_does_not_lock_other_accounts(self):
        first = self._login('alice', '100.64.0.3', remote_addr='10.42.0.5')
        self.assertEqual(first.status_code, status.HTTP_401_UNAUTHORIZED)

        second = self._login('bob', '100.64.0.3', remote_addr='10.42.0.5')
        self.assertEqual(second.status_code, status.HTTP_401_UNAUTHORIZED)

    @override_settings(
        LOGIN_PASSWORD_IP_EXEMPT_CIDRS='100.64.0.3/32',
        LOGIN_PASSWORD_TRUSTED_PROXY_CIDRS='10.0.0.0/8,100.64.0.0/10',
    )
    def test_trusted_internal_same_account_still_locks_on_account_budget(self):
        first = self._login('alice', '100.64.0.3', remote_addr='10.42.0.5')
        self.assertEqual(first.status_code, status.HTTP_401_UNAUTHORIZED)

        second = self._login('alice', '100.64.0.3', remote_addr='10.42.0.5')
        self.assertEqual(second.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertEqual(second.data['error'], 'too_many_login_attempts')

    @override_settings(
        LOGIN_PASSWORD_IP_EXEMPT_CIDRS='100.64.0.3/32',
        LOGIN_PASSWORD_TRUSTED_PROXY_CIDRS='10.0.0.0/8,100.64.0.0/10',
    )
    def test_public_same_ip_spray_still_locks_across_accounts(self):
        first = self._login('alice', '198.51.100.9', remote_addr='198.51.100.9')
        self.assertEqual(first.status_code, status.HTTP_401_UNAUTHORIZED)

        second = self._login('bob', '198.51.100.9', remote_addr='198.51.100.9')
        self.assertEqual(second.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertEqual(second.data['error'], 'too_many_login_attempts')

    @override_settings(
        LOGIN_PASSWORD_IP_EXEMPT_CIDRS='100.64.0.3/32',
        LOGIN_PASSWORD_TRUSTED_PROXY_CIDRS='10.0.0.0/8,100.64.0.0/10',
    )
    def test_spoofed_forwarded_internal_ip_from_untrusted_peer_does_not_bypass_ip_lockout(self):
        first = self._login('alice', '100.64.0.3', remote_addr='203.0.113.9')
        self.assertEqual(first.status_code, status.HTTP_401_UNAUTHORIZED)

        second = self._login('bob', '100.64.0.3', remote_addr='203.0.113.9')
        self.assertEqual(second.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertEqual(second.data['error'], 'too_many_login_attempts')

    @patch('identity.password_reset_security.send_password_reset_email_async')
    def test_reset_per_account_lockout_survives_ip_rotation(self, send_reset):
        first = self.client.post(
            '/api/auth/password/reset/', {'email': 'alice@example.com'},
            format='json', HTTP_X_FORWARDED_FOR='203.0.113.1',
        )
        self.assertEqual(first.status_code, status.HTTP_200_OK)

        second = self.client.post(
            '/api/auth/password/reset/', {'email': 'alice@example.com'},
            format='json', HTTP_X_FORWARDED_FOR='203.0.113.2',
        )
        self.assertEqual(second.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertEqual(second.data['message'], GENERIC)
        self.assertIn('retry_after', second.data)
        self.assertEqual(send_reset.call_count, 1)

    @patch('identity.password_reset_security.send_password_reset_email_async')
    def test_reset_per_ip_lockout_catches_spray_across_accounts(self, send_reset):
        first = self.client.post(
            '/api/auth/password/reset/', {'email': 'alice@example.com'},
            format='json', HTTP_X_FORWARDED_FOR='203.0.113.44',
        )
        self.assertEqual(first.status_code, status.HTTP_200_OK)

        second = self.client.post(
            '/api/auth/password/reset/', {'email': 'bob@example.com'},
            format='json', HTTP_X_FORWARDED_FOR='203.0.113.44',
        )
        self.assertEqual(second.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertEqual(second.data['message'], GENERIC)
        self.assertIn('retry_after', second.data)
        self.assertEqual(send_reset.call_count, 1)
