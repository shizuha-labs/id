"""PLAT-672 Phase 1: is_active hardening of the RS256 OAuth bearer authenticator.

This authenticator (used on UserinfoView) dual-verifies HS256 SimpleJWT + RS256
OAuth access tokens. PLAT-672 fixes a gap: it must enforce is_active (the HS256
SimpleJWT default does, via JWTAuthentication.get_user) so a disabled user's
still-valid token cannot authenticate on EITHER path. Pure-logic (no DB) —
User.objects.get is mocked.

IMPORTANT (ren security review): this class must NOT be the platform-wide default
authenticator — it accepts THIRD-PARTY OAuth tokens (aud=client_id, scope-limited,
aud/iss verification disabled); as the default that would allow audience-confusion
replay against unrelated APIs. The settings-guard test below pins that decision.
"""
from types import SimpleNamespace
from unittest.mock import patch

from django.conf import settings
from django.test import SimpleTestCase
from rest_framework.exceptions import AuthenticationFailed as DRFAuthFailed

from identity.authentication import RS256OAuthBearerAuthentication


class DefaultAuthenticatorScopingTests(SimpleTestCase):
    def test_rs256_oauth_bearer_is_not_the_global_default(self):
        # ren P1: the OAuth-token-accepting RS256 authenticator must stay scoped to
        # OAuth-scope-aware endpoints (userinfo), NOT the platform default — else a
        # third-party OAuth token (aud=client_id, scope='openid profile') could be
        # replayed against unrelated shizuha-id APIs as the user.
        default_classes = settings.REST_FRAMEWORK['DEFAULT_AUTHENTICATION_CLASSES']
        self.assertNotIn(
            'identity.authentication.RS256OAuthBearerAuthentication', default_classes,
            'RS256OAuthBearerAuthentication must not be the platform default (audience confusion).',
        )
        self.assertIn(
            'identity.authentication.OAuthClientRevocationJWTAuthentication', default_classes,
        )


def _http_request(header: bytes):
    # Minimal object exposing the headers DRF's get_authorization_header reads.
    return SimpleNamespace(META={'HTTP_AUTHORIZATION': header.decode()} if header else {})


class ResolveActiveUserTests(SimpleTestCase):
    def test_active_user_resolves(self):
        active = SimpleNamespace(pk=1, is_active=True)
        with patch('identity.authentication.User.objects.get', return_value=active):
            self.assertIs(RS256OAuthBearerAuthentication._resolve_active_user(1), active)

    def test_inactive_user_rejected(self):
        inactive = SimpleNamespace(pk=2, is_active=False)
        with patch('identity.authentication.User.objects.get', return_value=inactive):
            with self.assertRaises(DRFAuthFailed):
                RS256OAuthBearerAuthentication._resolve_active_user(2)

    def test_missing_user_id_rejected(self):
        with self.assertRaises(DRFAuthFailed):
            RS256OAuthBearerAuthentication._resolve_active_user(None)

    def test_unknown_user_rejected(self):
        from django.contrib.auth import get_user_model
        DoesNotExist = get_user_model().DoesNotExist
        with patch('identity.authentication.User.objects.get', side_effect=DoesNotExist):
            with self.assertRaises(DRFAuthFailed):
                RS256OAuthBearerAuthentication._resolve_active_user(999)


class DualVerifyAuthenticateTests(SimpleTestCase):
    def setUp(self):
        self.auth = RS256OAuthBearerAuthentication()

    def test_no_bearer_returns_none(self):
        self.assertIsNone(self.auth.authenticate(_http_request(b'')))

    def test_hs256_active_user_authenticates(self):
        active = SimpleNamespace(pk=1, is_active=True)
        validated = {'user_id': 1, 'token_type': 'access'}
        with patch('identity.authentication.OAuthClientRevocationJWTAuthentication.get_validated_token',
                   return_value=validated), \
             patch('identity.authentication.User.objects.get', return_value=active):
            user, token = self.auth.authenticate(_http_request(b'Bearer hs256.token.here'))
        self.assertIs(user, active)
        self.assertEqual(token, validated)

    def test_hs256_inactive_user_rejected(self):
        # A valid HS256 token for a DISABLED user must 401 — the regression this
        # guards before the class becomes the platform-wide default.
        inactive = SimpleNamespace(pk=2, is_active=False)
        with patch('identity.authentication.OAuthClientRevocationJWTAuthentication.get_validated_token',
                   return_value={'user_id': 2, 'token_type': 'access'}), \
             patch('identity.authentication.User.objects.get', return_value=inactive):
            with self.assertRaises(DRFAuthFailed):
                self.auth.authenticate(_http_request(b'Bearer hs256.token.here'))

    def test_malformed_header_rejected(self):
        with self.assertRaises(DRFAuthFailed):
            self.auth.authenticate(_http_request(b'Bearer'))  # single part
