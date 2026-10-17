"""
Tests for PLAT-255/PLAT-1179 RS256 platform token issuance.

Validates that:
  - Agent users receive RS256-signed JWTs with kid header + broker aud claim
  - Human/browser users receive RS256-signed JWTs with kid header + wildcard aud claim
  - Newly minted tokens carry the canonical issuer while pre-fix RS256 refreshes migrate
  - Legacy HS256 human refresh tokens upgrade to RS256 access+refresh tokens
  - Token verifies against the live JWKS public key (no shared secret)
"""
import json
from unittest import mock

import jwt as _pyjwt
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIRequestFactory
from rest_framework_simplejwt.exceptions import InvalidToken

from identity.authentication import OAuthClientRevocationJWTAuthentication
from identity.agent_tokens import (
    BROKER_RELAY_AUD,
    AgentAccessToken,
    AgentRefreshToken,
    PlatformAccessToken,
    PlatformRefreshToken,
    _get_agent_backend,
)
from identity.oauth_keys import get_signing_material, build_jwks
from identity.models import UserProfile
from identity.views import UserView, get_tokens_for_user

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

# Minimal settings override so the test suite doesn't need a real DB for
# oauth_keys path (the key dir defaults to /var/shizuha/oauth-keys; tests
# use a temp dir via env if needed, but key-less unit tests avoid the path).
_TEST_OVERRIDES = {}


def _set_account_type(user, account_type):
    profile, _ = UserProfile.objects.get_or_create(user=user)
    profile.account_type = account_type
    profile.save(update_fields=['account_type'])
    # UserProfile is auto-created by a signal as "human"; if the one-to-one
    # relation was cached during user creation, clear it so _is_agent_user()
    # observes the updated profile.
    user._state.fields_cache.pop('profile', None)
    return profile


def _make_user(username, account_type='human', is_staff=False):
    """Create a token-capable user.

    SimpleJWT's blacklist app records OutstandingToken rows for refresh tokens,
    so token issuance needs a real saved User instance rather than a MagicMock.
    """
    user = User.objects.create_user(
        username=username,
        email=(
            f'{username}@agents.shizuha.io'
            if account_type == 'agent'
            else f'{username}@shizuha.com'
        ),
        password='pw',
        first_name='Test',
        last_name='User',
        is_staff=is_staff,
    )
    _set_account_type(user, account_type)
    return user


class AgentTokenBackendTests(TestCase):
    """Unit tests for _AgentTokenBackend — no DB needed."""

    def test_encode_alg_rs256(self):
        backend = _get_agent_backend()
        payload = {'user_id': 99, 'token_type': 'access', 'exp': 9999999999, 'iat': 0, 'jti': 'x'}
        token_str = backend.encode(payload)
        header = _pyjwt.get_unverified_header(token_str)
        self.assertEqual(header['alg'], 'RS256')

    def test_encode_includes_kid(self):
        backend = _get_agent_backend()
        material = get_signing_material()
        payload = {'user_id': 99, 'token_type': 'access', 'exp': 9999999999, 'iat': 0, 'jti': 'x'}
        token_str = backend.encode(payload)
        header = _pyjwt.get_unverified_header(token_str)
        self.assertEqual(header['kid'], material['kid'])

    def test_encode_includes_broker_aud(self):
        backend = _get_agent_backend()
        payload = {'user_id': 99, 'token_type': 'access', 'exp': 9999999999, 'iat': 0, 'jti': 'x'}
        token_str = backend.encode(payload)
        claims = _pyjwt.decode(
            token_str,
            get_signing_material()['public_pem'],
            algorithms=['RS256'],
            audience=BROKER_RELAY_AUD,
        )
        self.assertEqual(claims['aud'], BROKER_RELAY_AUD)
        self.assertEqual(claims['iss'], 'https://shizuha.com/id')

    def test_verifies_against_jwks_public_key(self):
        """Token produced by the backend must verify with the JWKS public key."""
        backend = _get_agent_backend()
        payload = {'user_id': 99, 'token_type': 'access', 'exp': 9999999999, 'iat': 0, 'jti': 'x'}
        token_str = backend.encode(payload)
        material = get_signing_material()
        # Simulate what a JWKS-aware verifier does: fetch public key via kid,
        # verify signature. Here we use the public PEM directly (same key).
        claims = _pyjwt.decode(
            token_str,
            material['public_pem'],
            algorithms=['RS256'],
            audience=BROKER_RELAY_AUD,
        )
        self.assertEqual(claims['user_id'], 99)

    def test_hs_key_not_in_jwks(self):
        """JWKS must only expose RSA public keys, never HS keys."""
        jwks = build_jwks()
        for key in jwks['keys']:
            self.assertEqual(key['kty'], 'RSA', "JWKS must not expose HS (symmetric) keys")
            self.assertEqual(key['alg'], 'RS256')

    def test_kid_matches_jwks_entry(self):
        """kid in a minted token must map to a key in the JWKS document."""
        backend = _get_agent_backend()
        payload = {'user_id': 99, 'token_type': 'access', 'exp': 9999999999, 'iat': 0, 'jti': 'x'}
        token_str = backend.encode(payload)
        header = _pyjwt.get_unverified_header(token_str)
        kid = header['kid']
        jwks = build_jwks()
        jwks_kids = {k['kid'] for k in jwks['keys']}
        self.assertIn(kid, jwks_kids)


class AgentTokenClassTests(TestCase):
    """AgentAccessToken / AgentRefreshToken use the RS256 backend."""

    def test_agent_access_token_is_rs256(self):
        tok = AgentAccessToken()
        tok['user_id'] = 7
        header = _pyjwt.get_unverified_header(str(tok))
        self.assertEqual(header['alg'], 'RS256')

    def test_agent_refresh_token_is_rs256(self):
        tok = AgentRefreshToken()
        tok['user_id'] = 7
        header = _pyjwt.get_unverified_header(str(tok))
        self.assertEqual(header['alg'], 'RS256')

    def test_agent_refresh_access_token_class(self):
        self.assertIs(AgentRefreshToken.access_token_class, AgentAccessToken)

    def test_agent_access_token_decode_roundtrip(self):
        tok = AgentAccessToken()
        tok['user_id'] = 7
        tok_str = str(tok)
        # Decode using the RS256 backend — must not raise
        decoded = AgentAccessToken(tok_str)
        self.assertEqual(decoded['user_id'], 7)

    def test_platform_access_token_is_rs256(self):
        tok = PlatformAccessToken()
        tok['user_id'] = 3
        header = _pyjwt.get_unverified_header(str(tok))
        self.assertEqual(header['alg'], 'RS256')
        self.assertIn('kid', header)

    def test_platform_access_token_has_wildcard_aud(self):
        tok = PlatformAccessToken()
        tok['user_id'] = 3
        claims = _pyjwt.decode(
            str(tok),
            get_signing_material()['public_pem'],
            algorithms=['RS256'],
            audience='*',
        )
        self.assertEqual(claims['aud'], '*')
        self.assertEqual(claims['iss'], 'https://shizuha.com/id')

    def test_platform_refresh_access_token_class(self):
        self.assertIs(PlatformRefreshToken.access_token_class, PlatformAccessToken)


class GetTokensForUserTests(TestCase):
    """get_tokens_for_user() issues RS256 for all first-party principals."""

    def _mock_db(self, user):
        """Patch DB calls made during token population."""
        from unittest.mock import patch
        patches = [
            patch('identity.views.Tool.objects.filter', return_value=[]),
            patch('identity.views._fetch_org_memberships', return_value={}),
        ]
        return patches

    def test_agent_gets_rs256_access_token(self):
        user = _make_user('ren', account_type='agent')
        from unittest.mock import patch, MagicMock
        with patch('identity.views.Tool.objects.filter') as mf, \
             patch('identity.views._fetch_org_memberships', return_value={}):
            mf.return_value.values_list.return_value = []
            mf.return_value.filter.return_value.values_list.return_value = []
            tokens = get_tokens_for_user(user)
        header = _pyjwt.get_unverified_header(tokens['access'])
        self.assertEqual(header['alg'], 'RS256')
        self.assertIn('kid', header)

    def test_human_gets_rs256_access_token(self):
        user = _make_user('hritik', account_type='human')
        from unittest.mock import patch
        with patch('identity.views.Tool.objects.filter') as mf, \
             patch('identity.views._fetch_org_memberships', return_value={}):
            mf.return_value.values_list.return_value = []
            mf.return_value.filter.return_value.values_list.return_value = []
            tokens = get_tokens_for_user(user)
        header = _pyjwt.get_unverified_header(tokens['access'])
        self.assertEqual(header['alg'], 'RS256')
        self.assertIn('kid', header)

    def test_agent_access_token_has_broker_aud(self):
        user = _make_user('kai', account_type='agent')
        from unittest.mock import patch
        with patch('identity.views.Tool.objects.filter') as mf, \
             patch('identity.views._fetch_org_memberships', return_value={}):
            mf.return_value.values_list.return_value = []
            mf.return_value.filter.return_value.values_list.return_value = []
            tokens = get_tokens_for_user(user)
        material = get_signing_material()
        claims = _pyjwt.decode(
            tokens['access'],
            material['public_pem'],
            algorithms=['RS256'],
            audience=BROKER_RELAY_AUD,
        )
        self.assertEqual(claims['aud'], BROKER_RELAY_AUD)

    def test_human_access_token_has_wildcard_aud(self):
        user = _make_user('operator', account_type='human')
        from unittest.mock import patch
        with patch('identity.views.Tool.objects.filter') as mf, \
             patch('identity.views._fetch_org_memberships', return_value={}):
            mf.return_value.values_list.return_value = []
            mf.return_value.filter.return_value.values_list.return_value = []
            tokens = get_tokens_for_user(user)
        material = get_signing_material()
        claims = _pyjwt.decode(
            tokens['access'],
            material['public_pem'],
            algorithms=['RS256'],
            audience='*',
        )
        self.assertEqual(claims['aud'], '*')
        self.assertEqual(claims['iss'], 'https://shizuha.com/id')

    def test_agent_refresh_token_is_rs256(self):
        user = _make_user('akira', account_type='agent')
        from unittest.mock import patch
        with patch('identity.views.Tool.objects.filter') as mf, \
             patch('identity.views._fetch_org_memberships', return_value={}):
            mf.return_value.values_list.return_value = []
            mf.return_value.filter.return_value.values_list.return_value = []
            tokens = get_tokens_for_user(user)
        header = _pyjwt.get_unverified_header(tokens['refresh'])
        self.assertEqual(header['alg'], 'RS256')

    def test_storm_aware_refresh_view_accepts_agent_rs256_refresh(self):
        """The live /auth/refresh/ view must use the RS256-aware Shizuha serializer."""
        from unittest.mock import patch
        from identity.storm_views import StormAwareTokenRefreshView

        user = User.objects.create_user(username='kai-agent', email='kai@shizuha.com', password='pw')
        _set_account_type(user, 'agent')
        with patch('identity.views.Tool.objects.filter') as mf, \
             patch('identity.views._fetch_org_memberships', return_value={}), \
             patch('identity.storm_views.get_strategy') as strategy:
            mf.return_value.values_list.return_value = []
            mf.return_value.filter.return_value.values_list.return_value = []
            strategy.return_value.record.return_value.should_emit = False
            tokens = get_tokens_for_user(user)

            request = APIRequestFactory().post('/id/api/auth/refresh/', {'refresh': tokens['refresh']}, format='json')
            response = StormAwareTokenRefreshView.as_view()(request)

        self.assertEqual(response.status_code, 200)
        self.assertIn('access', response.data)
        self.assertEqual(_pyjwt.get_unverified_header(response.data['access'])['alg'], 'RS256')

    def test_legacy_human_hs256_refresh_upgrades_to_rs256_pair(self):
        """Existing human sessions migrate on refresh instead of forcing re-login."""
        from unittest.mock import patch
        from identity.storm_views import StormAwareTokenRefreshView
        from rest_framework_simplejwt.tokens import RefreshToken

        user = _make_user('legacy-human', account_type='human')
        legacy_refresh = RefreshToken.for_user(user)
        legacy_refresh['email'] = user.email
        legacy_refresh['username'] = user.username

        with patch('identity.views.Tool.objects.filter') as mf, \
             patch('identity.views._fetch_org_memberships', return_value={}), \
             patch('identity.storm_views.get_strategy') as strategy:
            mf.return_value.values_list.return_value = []
            mf.return_value.filter.return_value.values_list.return_value = []
            strategy.return_value.record.return_value.should_emit = False
            request = APIRequestFactory().post(
                '/id/api/auth/refresh/', {'refresh': str(legacy_refresh)}, format='json'
            )
            response = StormAwareTokenRefreshView.as_view()(request)

        self.assertEqual(response.status_code, 200)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertEqual(_pyjwt.get_unverified_header(response.data['access'])['alg'], 'RS256')
        self.assertEqual(_pyjwt.get_unverified_header(response.data['refresh'])['alg'], 'RS256')

    def test_issuerless_rs256_refresh_upgrades_without_session_breakage(self):
        """Pre-BKS-167 RS256 sessions refresh into canonical issuer-bearing JWTs."""
        from unittest.mock import patch
        from identity.storm_views import StormAwareTokenRefreshView

        user = _make_user('legacy-rs256-human', account_type='human')
        legacy_refresh = PlatformRefreshToken.for_user(user)
        legacy_refresh['email'] = user.email
        legacy_refresh['username'] = user.username
        material = get_signing_material()
        issuerless = _pyjwt.encode(
            {**legacy_refresh.payload, 'aud': '*'},
            material['private_pem'],
            algorithm='RS256',
            headers={'kid': material['kid']},
        )

        with patch('identity.views.Tool.objects.filter') as tools, \
             patch('identity.views._fetch_org_memberships', return_value={}), \
             patch('identity.storm_views.get_strategy') as strategy:
            tools.return_value.values_list.return_value = []
            tools.return_value.filter.return_value.values_list.return_value = []
            strategy.return_value.record.return_value.should_emit = False
            request = APIRequestFactory().post(
                '/id/api/auth/refresh/',
                {'refresh': issuerless},
                format='json',
            )
            response = StormAwareTokenRefreshView.as_view()(request)

        self.assertEqual(response.status_code, 200)
        for field in ('access', 'refresh'):
            claims = _pyjwt.decode(
                response.data[field],
                material['public_pem'],
                algorithms=['RS256'],
                audience='*',
            )
            self.assertEqual(claims['iss'], 'https://shizuha.com/id')


class AgentDefaultAuthenticationTests(TestCase):
    """Default ID API auth accepts first-party RS256 platform tokens."""

    def _agent_user(self):
        user = User.objects.create_user(
            username='id28-agent',
            email='id28-agent@agents.shizuha.io',
            password='pw',
            is_staff=True,
        )
        _set_account_type(user, 'agent')
        return user

    def _mint_agent_tokens(self, user):
        from unittest.mock import patch
        with patch('identity.views.Tool.objects.filter') as mf, \
             patch('identity.views._fetch_org_memberships', return_value={}):
            mf.return_value.values_list.return_value = []
            mf.return_value.filter.return_value.values_list.return_value = []
            return get_tokens_for_user(user)

    def test_default_auth_accepts_login_issued_agent_access_token_on_user_endpoint(self):
        user = self._agent_user()
        tokens = self._mint_agent_tokens(user)

        request = APIRequestFactory().get(
            '/id/api/auth/user/',
            HTTP_AUTHORIZATION=f'Bearer {tokens["access"]}',
        )
        response = UserView.as_view()(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['email'], user.email)

    def test_default_auth_accepts_refresh_issued_agent_access_token_on_user_endpoint(self):
        from unittest.mock import patch
        from identity.storm_views import StormAwareTokenRefreshView

        user = self._agent_user()
        tokens = self._mint_agent_tokens(user)

        refresh_request = APIRequestFactory().post(
            '/id/api/auth/refresh/',
            {'refresh': tokens['refresh']},
            format='json',
        )
        with patch('identity.storm_views.get_strategy') as strategy:
            strategy.return_value.record.return_value.should_emit = False
            refresh_response = StormAwareTokenRefreshView.as_view()(refresh_request)

        self.assertEqual(refresh_response.status_code, 200)
        self.assertIn('access', refresh_response.data)

        user_request = APIRequestFactory().get(
            '/id/api/auth/user/',
            HTTP_AUTHORIZATION=f'Bearer {refresh_response.data["access"]}',
        )
        user_response = UserView.as_view()(user_request)

        self.assertEqual(user_response.status_code, 200)
        self.assertEqual(user_response.data['email'], user.email)

    def test_default_auth_rejects_rs256_oauth_token_with_non_broker_audience(self):
        material = get_signing_material()
        token = _pyjwt.encode(
            {
                'user_id': 42,
                'token_type': 'access',
                'exp': 9999999999,
                'iat': 0,
                'jti': 'oauth-client-token',
                'client_id': 'third-party-client',
                'scope': 'openid profile',
                'aud': 'third-party-client',
            },
            material['private_pem'],
            algorithm='RS256',
            headers={'kid': material['kid']},
        )

        with self.assertRaises(InvalidToken):
            OAuthClientRevocationJWTAuthentication().get_validated_token(token)
