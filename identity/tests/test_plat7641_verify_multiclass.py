"""PLAT-7641: /api/auth/verify/ must accept every token class the auth path accepts.

Live defect (PLAT-7634 T1 cadence, 2026-09-04): the stock TokenVerifyView
decoded every token with the GLOBAL simplejwt backend (SIMPLE_JWT['ALGORITHM']
= HS256 / SIGNING_KEY). Since PLAT-255 / PLAT-1179, interactive logins mint
RS256 tokens (AgentRefreshToken / PlatformRefreshToken, aud='*' or
'shizuha:broker-relay'), so /verify/ signature-checked an RS256 token as HS256
and false-rejected 100% of live tokens (401 token_not_valid) while
/api/auth/user/ accepted the identical token via AUTH_TOKEN_CLASSES.

The fix (MultiClassTokenVerifyView) validates the token under the same token
classes the authenticator accepts, preserving the PLAT-166 contract:
signature+expiry only, 200 = valid / 401 = invalid / 400 = blacklisted.

These tests pin the exact live-repro shape: the SAME access token that the
authenticated surface accepts must verify 200, back to back.
"""
import os

os.environ.setdefault('SHIZUHA_OAUTH_KEY_DIR', '/tmp/shizuha-plat7641-oauth-keys')

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework_simplejwt.tokens import RefreshToken

from identity.views import get_tokens_for_user

User = get_user_model()

VERIFY_URL = '/api/auth/verify/'
USER_URL = '/api/auth/user/'


def _user(username, email=None, **kwargs):
    return User.objects.create_user(
        username=username, email=email or f'{username}@shizuha.com', password='Pass123!x',
        **kwargs,
    )


def _make_agent(user):
    """Agent account per the profile account_type contract (PLAT-671)."""
    user.profile.account_type = 'agent'
    user.profile.save(update_fields=['account_type'])
    return user


def _tokens_for(user):
    """Mint via the real login path with the membership projection stubbed
    (same convention as test_plat5996_token_version)."""
    from unittest import mock
    with mock.patch('identity.views._fetch_org_memberships', return_value={}), \
         mock.patch('identity.views._fetch_project_memberships', return_value=([], {})):
        return get_tokens_for_user(user)


class MultiClassVerifyTests(TestCase):
    def _verify(self, token):
        return self.client.post(
            VERIFY_URL, {'token': token}, content_type='application/json',
        )

    def test_rs256_platform_access_token_verifies_200(self):
        """Human login token (RS256, aud='*') must verify — the live repro."""
        user = _user('plat7641_human')
        tokens = _tokens_for(user)
        response = self._verify(tokens['access'])
        self.assertEqual(response.status_code, 200, response.content)

    def test_rs256_agent_access_token_verifies_200(self):
        """Agent login token (RS256, aud='shizuha:broker-relay') must verify."""
        user = _make_agent(_user('plat7641_agent', email='plat7641_agent@agents.shizuha.io'))
        tokens = _tokens_for(user)
        response = self._verify(tokens['access'])
        self.assertEqual(response.status_code, 200, response.content)

    def test_verify_accepts_what_user_endpoint_accepts_back_to_back(self):
        """The exact PLAT-7641 live-repro shape: /user/ 200 <=> /verify/ 200."""
        user = _user('plat7641_parity')
        tokens = _tokens_for(user)
        access = tokens['access']
        user_response = self.client.get(
            USER_URL, HTTP_AUTHORIZATION=f'Bearer {access}',
        )
        self.assertEqual(user_response.status_code, 200, user_response.content)
        verify_response = self._verify(access)
        self.assertEqual(verify_response.status_code, 200, verify_response.content)

    def test_legacy_stock_hs256_access_token_still_verifies_200(self):
        """Backward compat: stock HS256 tokens (pre-RS256 mint paths) verify."""
        user = _user('plat7641_legacy')
        access = str(RefreshToken.for_user(user).access_token)
        response = self._verify(access)
        self.assertEqual(response.status_code, 200, response.content)

    def test_rs256_refresh_token_verifies_200(self):
        """The stock view accepted decodable refresh tokens; surface keeps that."""
        user = _user('plat7641_refresh')
        tokens = _tokens_for(user)
        response = self._verify(tokens['refresh'])
        self.assertEqual(response.status_code, 200, response.content)

    def test_tampered_token_fails_closed_401(self):
        """Fail-closed: a one-character signature tamper must 401, not 200."""
        user = _user('plat7641_tamper')
        tokens = _tokens_for(user)
        token = tokens['access']
        tampered = token[:-3] + ('aaa' if token[-3:] != 'aaa' else 'bbb')
        response = self._verify(tampered)
        self.assertEqual(response.status_code, 401, response.content)
        self.assertEqual(response.data.get('code'), 'token_not_valid')

    def test_garbage_token_fails_closed_401(self):
        response = self._verify('not-a-jwt')
        self.assertEqual(response.status_code, 401, response.content)
        self.assertEqual(response.data.get('code'), 'token_not_valid')

    def test_missing_token_field_400(self):
        """Input contract preserved from the stock view (missing field -> 400)."""
        response = self.client.post(VERIFY_URL, {}, content_type='application/json')
        self.assertEqual(response.status_code, 400, response.content)

    def test_blacklisted_refresh_token_reports_blacklisted_400(self):
        """Stock blacklist behaviour preserved: blacklisted jti -> 400."""
        user = _user('plat7641_blacklist')
        refresh = RefreshToken.for_user(user)
        refresh.blacklist()
        response = self._verify(str(refresh))
        self.assertEqual(response.status_code, 400, response.content)
        self.assertIn('blacklist', str(response.data).lower())
