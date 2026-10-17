"""PLAT-5996 (ID-1 §3.1 primary): monotonic ``token_version`` claim end-to-end.

ID mints a monotonic ``token_version`` claim on every access token, increments
it inside ``revoke_all_user_tokens`` (same transaction as the
``access_revoked_before`` cutoff), and exposes the subject's CURRENT version via
``/api/oauth/revocation-status`` so consumers (Pulse, Hive, every RS256
verifier) can reject a replayed pre-revocation token even when the OAuth-store
row is gone (revive-by-replay).

These tests cover the ID side of the contract:
  1. mint: every access token carries ``token_version`` (0 for a fresh user).
  2. revoke: ``revoke_all_user_tokens`` increments the stored version.
  3. status: the revocation-status endpoint returns the subject's CURRENT
     version for user tokens (no client_id) so consumers can compare.
  4. consumer-boundary: a token minted BEFORE a revoke carries an older version
     than the current one (the exact condition consumers reject on).
"""
from datetime import datetime, timedelta, timezone as dt_timezone
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIRequestFactory

from identity import oauth_views
from identity.models import UserProfile
from identity.views import _current_token_version, get_tokens_for_user, revoke_all_user_tokens

User = get_user_model()


def _user(username, **kwargs):
    return User.objects.create_user(
        username=username, email=f'{username}@shizuha.com', password='Pass123!x',
        **kwargs,
    )


class TokenVersionMintTests(TestCase):
    def test_login_access_token_carries_token_version_claim(self):
        user = _user('v1-user')
        with mock.patch('identity.views._fetch_org_memberships', return_value={}), \
             mock.patch('identity.views._fetch_project_memberships', return_value=([], {})):
            tokens = get_tokens_for_user(user)
        access = tokens['access']
        # Access token is RS256; decode via the platform backend is complex, so
        # assert the claim is present in the raw payload through the same decode
        # helper the status endpoint uses.
        payload = oauth_views._decode_oauth_access_token_for_status(access)
        self.assertIsNotNone(payload)
        self.assertEqual(payload.get('token_version'), 0)

    def test_token_version_reads_from_profile(self):
        user = _user('v2-user')
        UserProfile.objects.filter(user=user).update(token_version=7)
        user.profile.refresh_from_db()
        self.assertEqual(_current_token_version(user), 7)


class TokenVersionRevokeTests(TestCase):
    def test_revoke_increments_token_version(self):
        user = _user('v3-user')
        profile = user.profile
        self.assertEqual(profile.token_version, 0)

        revoke_all_user_tokens(user)
        profile.refresh_from_db()
        self.assertEqual(profile.token_version, 1)

        revoke_all_user_tokens(user)
        profile.refresh_from_db()
        self.assertEqual(profile.token_version, 2)

    def test_pre_revoke_token_has_older_version_than_current(self):
        """Consumer-boundary condition: a token minted before a revoke carries a
        strictly smaller token_version than the current one — the exact state a
        consumer rejects on."""
        user = _user('v4-user')
        with mock.patch('identity.views._fetch_org_memberships', return_value={}), \
             mock.patch('identity.views._fetch_project_memberships', return_value=([], {})):
            before = get_tokens_for_user(user)
        before_payload = oauth_views._decode_oauth_access_token_for_status(before['access'])
        self.assertEqual(before_payload.get('token_version'), 0)

        revoke_all_user_tokens(user)
        user.profile.refresh_from_db()
        self.assertEqual(user.profile.token_version, 1)

        with mock.patch('identity.views._fetch_org_memberships', return_value={}), \
             mock.patch('identity.views._fetch_project_memberships', return_value=([], {})):
            after = get_tokens_for_user(user)
        after_payload = oauth_views._decode_oauth_access_token_for_status(after['access'])
        self.assertEqual(after_payload.get('token_version'), 1)

        # The pre-revoke token's version (0) < current (1) → a consumer must
        # reject it. This is the revive-by-replay closure.
        self.assertLess(before_payload.get('token_version'), user.profile.token_version)


class TokenVersionStatusEndpointTests(TestCase):
    def test_status_returns_current_version_for_user_token(self):
        user = _user('v5-user')
        UserProfile.objects.filter(user=user).update(token_version=3)
        with mock.patch('identity.views._fetch_org_memberships', return_value={}), \
             mock.patch('identity.views._fetch_project_memberships', return_value=([], {})):
            tokens = get_tokens_for_user(user)
        request = APIRequestFactory().post(
            '/id/api/oauth/revocation-status',
            {'token': tokens['access']},
            format='json',
        )
        resp = oauth_views.OAuthRevocationStatusView.as_view()(request)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data['active'], True)
        self.assertEqual(resp.data['token_version'], 3)

    def test_status_returns_bumped_version_after_revoke(self):
        user = _user('v6-user')
        # JWT iat is second-resolution. Model a token issued strictly after
        # the authoritative cutoff, not within the revoked second.
        with mock.patch('identity.views.timezone.now',
                        return_value=timezone.now() - timedelta(seconds=2)):
            revoke_all_user_tokens(user)
        with mock.patch('identity.views._fetch_org_memberships', return_value={}), \
             mock.patch('identity.views._fetch_project_memberships', return_value=([], {})):
            tokens = get_tokens_for_user(user)
        request = APIRequestFactory().post(
            '/id/api/oauth/revocation-status',
            {'token': tokens['access']},
            format='json',
        )
        resp = oauth_views.OAuthRevocationStatusView.as_view()(request)
        self.assertEqual(resp.data['active'], True)
        self.assertEqual(resp.data['token_version'], 1)

    def test_status_unknown_token_inactive(self):
        request = APIRequestFactory().post(
            '/id/api/oauth/revocation-status',
            {'token': 'not-a-jwt'},
            format='json',
        )
        resp = oauth_views.OAuthRevocationStatusView.as_view()(request)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data['active'], False)
        self.assertEqual(resp.data['token_version'], 0)
