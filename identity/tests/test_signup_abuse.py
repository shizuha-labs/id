"""Signup abuse: Turnstile, honeypot, disposable mail, IP/subnet/domain caps."""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import RequestFactory, TestCase, override_settings
from rest_framework.test import APIClient

from identity.models import Tool
from identity.signup_abuse import (
    GENERIC_DENIED,
    check_signup_rate,
    is_disposable_email,
    reject_signup,
    signup_config,
)

User = get_user_model()
REGISTER = '/api/auth/register/'
PASSWORD = 'Str0ng!Pass-signup-abuse-1'


def _req(data, ip='203.0.113.10'):
    factory = RequestFactory()
    request = factory.post('/api/auth/register/', data, format='json')
    request.data = data
    request.META['REMOTE_ADDR'] = ip
    return request


@override_settings(TURNSTILE_REQUIRED=False, TURNSTILE_SECRET='', TURNSTILE_SITE_KEY='')
class SignupAbuseUnitTests(TestCase):
    def setUp(self):
        cache.clear()

    def test_disposable_domains_are_rejected(self):
        self.assertTrue(is_disposable_email('bot@mailinator.com'))
        self.assertTrue(is_disposable_email('a@guerrillamail.com'))
        self.assertFalse(is_disposable_email('test-owner@example.com'))

    def test_honeypot_trips(self):
        denied = reject_signup(
            _req({'website': 'https://spam.example', 'email': 'a@gmail.com'}),
            email='a@gmail.com',
        )
        self.assertIsNotNone(denied)
        self.assertEqual(denied['code'], 'signup_denied')

    def test_rate_limit_ip(self):
        with override_settings(SIGNUP_RATE_LIMITS_ENABLED=True, SIGNUP_IP_MAX_PER_WINDOW=2, SIGNUP_WINDOW_SECONDS=3600):
            cache.clear()
            r = _req({}, ip='198.51.100.7')
            self.assertIsNone(check_signup_rate(r, 'one@gmail.com'))
            from identity.signup_abuse import record_signup
            record_signup(r, 'one@gmail.com')
            record_signup(r, 'two@gmail.com')
            hit = check_signup_rate(r, 'three@gmail.com')
            self.assertIsNotNone(hit)
            self.assertEqual(hit.dimension, 'ip')

    @override_settings(TURNSTILE_REQUIRED=True, TURNSTILE_SECRET='test-secret')
    def test_captcha_required_rejects_missing_token(self):
        denied = reject_signup(_req({}), email='ok@gmail.com', captcha_token='')
        self.assertIsNotNone(denied)

    @override_settings(TURNSTILE_REQUIRED=True, TURNSTILE_SECRET='test-secret')
    @patch('identity.signup_abuse.verify_turnstile', return_value=(True, 'ok'))
    def test_captcha_required_accepts_verified_token(self, _verify):
        denied = reject_signup(_req({}), email='ok@gmail.com', captcha_token='tok')
        self.assertIsNone(denied)

    def test_signup_config_hides_empty_sitekey(self):
        cfg = signup_config()
        self.assertFalse(cfg['captcha']['required'])
        self.assertFalse(cfg['open_registration'])
        self.assertTrue(cfg['approval_required'])


class RegisterAbuseEndpointTests(TestCase):
    def setUp(self):
        cache.clear()
        for slug in ('id', 'hive', 'mail'):
            Tool.objects.update_or_create(
                slug=slug,
                defaults={'display_name': slug, 'is_active': True, 'is_default_enabled': True},
            )
        self.client = APIClient()

    def _body(self, username, email, **extra):
        data = {
            'username': username,
            'email': email,
            'password': PASSWORD,
            'password2': PASSWORD,
        }
        data.update(extra)
        return data

    @override_settings(TURNSTILE_REQUIRED=False)
    def test_register_still_pending_without_open_flag(self):
        resp = self.client.post(
            REGISTER, self._body('freshuser', 'freshuser@example.com'), format='json',
        )
        self.assertEqual(resp.status_code, 201, resp.data)
        self.assertTrue(resp.data['pending_approval'])
        user = User.objects.get(username='freshuser')
        self.assertFalse(user.is_active)
        self.assertEqual(user.profile.approval_status, 'pending')

    @override_settings(TURNSTILE_REQUIRED=False)
    def test_honeypot_does_not_create_user(self):
        resp = self.client.post(
            REGISTER,
            self._body('honeypot', 'honeypot@example.com', website='http://bots.test'),
            format='json',
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.data['error'], GENERIC_DENIED)
        self.assertFalse(User.objects.filter(username='honeypot').exists())

    @override_settings(TURNSTILE_REQUIRED=False)
    def test_disposable_email_does_not_create_user(self):
        resp = self.client.post(
            REGISTER, self._body('tempbot', 'tempbot@mailinator.com'), format='json',
        )
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(User.objects.filter(username='tempbot').exists())

    @override_settings(TURNSTILE_REQUIRED=False, SIGNUP_RATE_LIMITS_ENABLED=True, SIGNUP_IP_MAX_PER_WINDOW=2, SIGNUP_WINDOW_SECONDS=3600)
    def test_third_signup_from_same_ip_is_blocked(self):
        for i in range(2):
            resp = self.client.post(
                REGISTER,
                self._body(f'ipuser{i}', f'ipuser{i}@example.com'),
                format='json',
                REMOTE_ADDR='203.0.113.88',
            )
            self.assertEqual(resp.status_code, 201, resp.data)
        resp = self.client.post(
            REGISTER,
            self._body('ipuser2', 'ipuser2@example.com'),
            format='json',
            REMOTE_ADDR='203.0.113.88',
        )
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(User.objects.filter(username='ipuser2').exists())

    @override_settings(TURNSTILE_REQUIRED=True, TURNSTILE_SECRET='s')
    @patch('identity.signup_abuse.verify_turnstile', return_value=(False, 'missing_token'))
    def test_register_requires_captcha_when_configured(self, _verify):
        resp = self.client.post(
            REGISTER, self._body('capuser', 'capuser@example.com'), format='json',
        )
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(User.objects.filter(username='capuser').exists())

    def test_signup_config_endpoint(self):
        resp = self.client.get('/api/auth/signup-config/')
        self.assertEqual(resp.status_code, 200)
        self.assertIn('captcha', resp.data)
        self.assertIn('approval_required', resp.data)
