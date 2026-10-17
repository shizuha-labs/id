"""HIVE-1987: QA fixture signup bypass.

Non-staff QA seats need a fresh blank-slate test user each cycle, but public
signup is Turnstile-gated (captcha.required=true) and QA has no staff/admin
access and no Turnstile-solving path. Emails in the configured
QA_FIXTURE_SIGNUP_DOMAIN skip the captcha (honeypot + rate limits still apply)
and are auto-approved/active so QA can register a usable user directly.
"""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework import status

from identity.models import Tool


REGISTER_URL = '/api/auth/register/'
PASSWORD = 'Str0ng!Pass-HIVE-1987-tests'
FIXTURE_DOMAIN = 'qafixture.shizuha.com'

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


def _seed_tools():
    for slug in ('id', 'drive', 'hive', 'pulse', 'connect', 'wiki', 'admin', 'fleet'):
        Tool.objects.update_or_create(
            slug=slug,
            defaults={
                'display_name': slug.title(),
                'is_active': True,
                'is_default_enabled': slug in {'id', 'hive'},
                'requires_approval': False,
                'requires_superuser': slug in {'admin', 'fleet'},
            },
        )


def _payload(username, email):
    return {
        'username': username,
        'email': email,
        'password': PASSWORD,
        'password2': PASSWORD,
        'first_name': 'QA',
        'last_name': 'Fixture',
    }


@override_settings(
    QA_FIXTURE_SIGNUP_DOMAIN=FIXTURE_DOMAIN,
    TURNSTILE_SECRET='test-secret',
    TURNSTILE_REQUIRED=True,
    SIGNUP_RATE_LIMITS_ENABLED=False,
)
class QaFixtureSignupTests(TestCase):
    def setUp(self):
        _seed_tools()

    @patch('identity.views._fetch_project_memberships', return_value=([], {}))
    @patch('identity.views._fetch_org_memberships', return_value={})
    @patch('identity.signup_abuse.verify_turnstile', return_value=(False, 'missing_token'))
    def test_fixture_email_skips_captcha_and_is_auto_approved(self, _verify, _orgs, _projects):
        """A fixture-domain email registers without a captcha token and is active."""
        response = self.client.post(
            REGISTER_URL,
            data=_payload('qafix1', f'qafix1@{FIXTURE_DOMAIN}'),
            content_type='application/json',
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        body = response.json()
        self.assertFalse(body['pending_approval'])
        self.assertIn('tokens', body)
        self.assertIn('access', body['tokens'])
        # The captcha verifier must never be reached for a fixture email.
        _verify.assert_not_called()

        user = get_user_model().objects.get(username='qafix1')
        self.assertTrue(user.is_active)
        self.assertEqual(user.profile.approval_status, 'approved')
        self.assertEqual(user.profile.lifecycle_state, 'active')

    @patch('identity.signup_abuse.verify_turnstile', return_value=(False, 'missing_token'))
    def test_public_email_still_requires_captcha(self, _verify):
        """A non-fixture email is still denied when captcha is required."""
        response = self.client.post(
            REGISTER_URL,
            data=_payload('pub1', 'pub1@example.com'),
            content_type='application/json',
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        body = response.json()
        self.assertEqual(body.get('code'), 'signup_denied')
        _verify.assert_called_once()

    @override_settings(QA_FIXTURE_SIGNUP_DOMAIN='')
    @patch('identity.signup_abuse.verify_turnstile', return_value=(False, 'missing_token'))
    def test_fixture_bypass_disabled_when_domain_unset(self, _verify):
        """When QA_FIXTURE_SIGNUP_DOMAIN is empty the bypass is off (fail-closed)."""
        response = self.client.post(
            REGISTER_URL,
            data=_payload('qafix2', f'qafix2@{FIXTURE_DOMAIN}'),
            content_type='application/json',
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        body = response.json()
        self.assertEqual(body.get('code'), 'signup_denied')
        _verify.assert_called_once()

    @patch('identity.signup_abuse.verify_turnstile', return_value=(False, 'missing_token'))
    def test_fixture_email_still_rejects_disposable_domain(self, _verify):
        """Fixture bypass does not whitelist disposable-mail domains."""
        response = self.client.post(
            REGISTER_URL,
            data=_payload('qafix3', 'qafix3@mailinator.com'),
            content_type='application/json',
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        body = response.json()
        self.assertEqual(body.get('code'), 'signup_denied')
