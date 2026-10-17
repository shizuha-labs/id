"""
ID-65: logout must durably blacklist the SUBMITTED refresh token (auth-bypass regression).

Live QA (2026-07-19) found ``POST /api/auth/logout/`` returned 200 while the
submitted refresh token stayed usable: ``LogoutView`` read only
``request.data['refresh']`` while the provider/QA contract sends
``refresh_token``, so the submitted token was silently ignored and only the
best-effort user-wide sweep ran. A logged-out session could keep minting access
tokens.

These regressions hit the REAL routed views (``/api/auth/refresh/`` ->
StormAwareTokenRefreshView, ``/api/auth/logout/`` -> LogoutView) in production
order across two top-level session attempts, per verify-before-push's
stateful-recurrence rule (the unit of regression is the caller SEQUENCE).
"""
from unittest import mock

import jwt
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase, APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from identity import invariants
from identity.models import PushToken, RevokedSession, ActiveSession, UserProfile

User = get_user_model()

REFRESH = '/api/auth/refresh/'
LOGOUT = '/api/auth/logout/'
LOGIN = '/api/auth/login/'
USERINFO = '/api/auth/user/'
PASSWORD_CHANGE = '/api/auth/password/change/'


class Id65LogoutBlacklistTests(APITestCase):
    def setUp(self):
        # Route counters are Redis-backed (see PLAT-1278); inject a fake so no
        # live Redis is required for the invariant counter.
        # These route tests only need the write-path metric sink to accept
        # ``incr``; keep the gate independent of the optional dev-only
        # ``fakeredis`` package used by dedicated invariant-metric tests.
        self.fake = mock.Mock()
        self._patch = mock.patch.object(invariants, '_redis_client', return_value=self.fake)
        self._patch.start()
        self.addCleanup(self._patch.stop)
        self._projection_patch = mock.patch(
            'identity.views._fetch_membership_projection',
            return_value=({}, [], {}),
        )
        self._projection_patch.start()
        self.addCleanup(self._projection_patch.stop)
        self.client = APIClient()

    def _user(self, username):
        return User.objects.create_user(
            username=username, email=f'{username}@shizuha.com', password='Pass123!x',
        )

    def _login(self, username):
        self.client.credentials()
        response = self.client.post(
            LOGIN,
            {'username': username, 'password': 'Pass123!x'},
            format='json',
        )
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()['tokens']

    def _claims(self, token):
        return jwt.decode(token, options={'verify_signature': False})

    def _userinfo(self, access):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access}')
        return self.client.get(USERINFO)

    def _refresh(self, refresh):
        self.client.credentials()
        self.client.raise_request_exception = False
        return self.client.post(REFRESH, {'refresh': refresh}, format='json')

    def _logout(self, tokens):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        self.client.raise_request_exception = False
        return self.client.post(
            LOGOUT,
            {'refresh_token': tokens['refresh']},
            format='json',
        )

    def _two_sessions(self, username):
        a = self._login(username)
        b = self._login(username)
        a_claims = self._claims(a['refresh'])
        b_claims = self._claims(b['refresh'])
        self.assertTrue(a_claims.get('sid'))
        self.assertTrue(b_claims.get('sid'))
        self.assertNotEqual(a_claims['sid'], b_claims['sid'])
        return a, b, a_claims['sid'], b_claims['sid']

    def test_id70_direct_logout_revokes_only_one_independent_session(self):
        """Production order: login A, login B, logout A, then probe both.

        A access+refresh are rejected; B access+refresh and push binding survive.
        Ordinary logout must not advance the user-wide revocation cutoff.
        """
        user = self._user('id70direct')
        a, b, sid_a, sid_b = self._two_sessions(user.username)
        push_a = PushToken.objects.create(
            user=user, token='ExponentPushToken[id70-a]', device_id='id70-a',
            platform='android', session_sid=sid_a,
        )
        push_b = PushToken.objects.create(
            user=user, token='ExponentPushToken[id70-b]', device_id='id70-b',
            platform='android', session_sid=sid_b,
        )
        self.assertEqual(self._userinfo(b['access']).status_code, 200)

        out = self._logout(a)
        self.assertEqual(out.status_code, 200, out.content)
        self.assertGreaterEqual(self._userinfo(a['access']).status_code, 400)
        self.assertGreaterEqual(self._refresh(a['refresh']).status_code, 400)
        self.assertEqual(self._userinfo(b['access']).status_code, 200)
        self.assertEqual(self._refresh(b['refresh']).status_code, 200)

        self.assertTrue(RevokedSession.objects.filter(user=user, sid=sid_a).exists())
        self.assertFalse(RevokedSession.objects.filter(user=user, sid=sid_b).exists())
        profile, _ = UserProfile.objects.get_or_create(user=user)
        self.assertIsNone(profile.access_revoked_before)
        push_a.refresh_from_db(); push_b.refresh_from_db()
        self.assertFalse(push_a.is_active)
        self.assertTrue(push_b.is_active)

    def test_id70_rotate_then_logout_keeps_sid_and_other_session(self):
        """Production order: login A/B, rotate A, logout rotated A, probe A/B."""
        user = self._user('id70rotate')
        a, b, sid_a, sid_b = self._two_sessions(user.username)

        rotated_response = self._refresh(a['refresh'])
        self.assertEqual(rotated_response.status_code, 200, rotated_response.content)
        rotated = rotated_response.json()
        self.assertEqual(self._claims(rotated['refresh'])['sid'], sid_a)
        self.assertEqual(self._claims(rotated['access'])['sid'], sid_a)
        self.assertGreaterEqual(self._refresh(a['refresh']).status_code, 400)

        out = self._logout(rotated)
        self.assertEqual(out.status_code, 200, out.content)
        self.assertGreaterEqual(self._userinfo(rotated['access']).status_code, 400)
        self.assertGreaterEqual(self._refresh(rotated['refresh']).status_code, 400)
        self.assertEqual(self._userinfo(b['access']).status_code, 200)
        b_rotated = self._refresh(b['refresh'])
        self.assertEqual(b_rotated.status_code, 200, b_rotated.content)
        self.assertEqual(self._claims(b_rotated.json()['refresh'])['sid'], sid_b)

    def test_id70_session_write_failure_rolls_back_exact_blacklist(self):
        """A DB failure must return non-200 and leave the submitted token usable."""
        user = self._user('id70rollback')
        a = self._login(user.username)
        with mock.patch(
            'identity.models.RevokedSession.objects.get_or_create',
            side_effect=RuntimeError('session ledger unavailable'),
        ):
            out = self._logout(a)
        self.assertEqual(out.status_code, 503, out.content)
        self.assertEqual(self._refresh(a['refresh']).status_code, 200)

    def test_id70_password_change_remains_account_wide(self):
        """The scoped logout split must not weaken password-change revocation."""
        user = self._user('id70password')
        a, b, _sid_a, _sid_b = self._two_sessions(user.username)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {a['access']}")
        response = self.client.post(
            PASSWORD_CHANGE,
            {
                'old_password': 'Pass123!x',
                'new_password': 'AnotherPass456!y',
                'new_password2': 'AnotherPass456!y',
            },
            format='json',
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertGreaterEqual(self._userinfo(a['access']).status_code, 400)
        self.assertGreaterEqual(self._userinfo(b['access']).status_code, 400)
        self.assertGreaterEqual(self._refresh(a['refresh']).status_code, 400)
        self.assertGreaterEqual(self._refresh(b['refresh']).status_code, 400)
        profile = UserProfile.objects.get(user=user)
        self.assertIsNotNone(profile.access_revoked_before)

    def test_logout_blacklists_submitted_refresh_then_reuse_rejected(self):
        """Path A (login -> logout -> reuse): logout blacklists the submitted
        refresh (sent as the canonical ``refresh_token``); reusing it fails."""
        user = self._user('id65a')
        refresh = str(RefreshToken.for_user(user))
        self.client.force_authenticate(user=user)
        resp = self.client.post(LOGOUT, {'refresh_token': refresh}, format='json')
        self.assertEqual(resp.status_code, 200, resp.content)
        self.client.force_authenticate(user=None)
        self.client.raise_request_exception = False
        reuse = self.client.post(REFRESH, {'refresh': refresh}, format='json')
        self.assertGreaterEqual(reuse.status_code, 400, reuse.content)

    def test_logout_blacklists_rotated_token_after_refresh_two_attempts(self):
        """Path B (login -> refresh(rotation) -> logout(rotated) -> reuse): the
        rotated token (RS256 platform token after the HS256->RS256 upgrade) is
        submitted to logout as ``refresh_token`` and must be durably blacklisted;
        reusing it fails. This is the exact reported production sequence, and the
        step where the bug returned 200 instead of 401."""
        user = self._user('id65b')
        login_refresh = str(RefreshToken.for_user(user))
        # rotate: the real refresh route returns a new (RS256) refresh
        rot = self.client.post(REFRESH, {'refresh': login_refresh}, format='json')
        self.assertEqual(rot.status_code, 200, rot.content)
        rotated_refresh = rot.json()['refresh']
        self.assertNotEqual(rotated_refresh, login_refresh)
        # control: the superseded login refresh is already blacklisted by rotation
        self.client.raise_request_exception = False
        superseded = self.client.post(REFRESH, {'refresh': login_refresh}, format='json')
        self.assertGreaterEqual(superseded.status_code, 400, superseded.content)
        # logout the ROTATED token via the canonical field
        self.client.force_authenticate(user=user)
        out = self.client.post(LOGOUT, {'refresh_token': rotated_refresh}, format='json')
        self.assertEqual(out.status_code, 200, out.content)
        # reuse the logged-out rotated token -> must be rejected (bug returned 200)
        self.client.force_authenticate(user=None)
        reuse = self.client.post(REFRESH, {'refresh': rotated_refresh}, format='json')
        self.assertGreaterEqual(reuse.status_code, 400, reuse.content)

    def test_logout_honors_deprecated_refresh_alias(self):
        """Backward compatibility: the legacy ``refresh`` field still logs out."""
        user = self._user('id65c')
        refresh = str(RefreshToken.for_user(user))
        self.client.force_authenticate(user=user)
        resp = self.client.post(LOGOUT, {'refresh': refresh}, format='json')
        self.assertEqual(resp.status_code, 200, resp.content)
        self.client.force_authenticate(user=None)
        self.client.raise_request_exception = False
        reuse = self.client.post(REFRESH, {'refresh': refresh}, format='json')
        self.assertGreaterEqual(reuse.status_code, 400, reuse.content)

    def test_logout_missing_token_returns_400_not_success(self):
        """A logout with no refresh token must fail loud, not silently 200."""
        user = self._user('id65d')
        self.client.force_authenticate(user=user)
        self.client.raise_request_exception = False
        resp = self.client.post(LOGOUT, {}, format='json')
        self.assertEqual(resp.status_code, 400, resp.content)

    def test_logout_rejects_another_users_token(self):
        """One user may not blacklist another user's refresh via logout."""
        owner = self._user('id65owner')
        attacker = self._user('id65attacker')
        owner_refresh = str(RefreshToken.for_user(owner))
        self.client.force_authenticate(user=attacker)
        self.client.raise_request_exception = False
        resp = self.client.post(LOGOUT, {'refresh_token': owner_refresh}, format='json')
        self.assertEqual(resp.status_code, 400, resp.content)
        # the owner's token must remain usable (attacker could not revoke it)
        self.client.force_authenticate(user=None)
        reuse = self.client.post(REFRESH, {'refresh': owner_refresh}, format='json')
        self.assertEqual(reuse.status_code, 200, reuse.content)

    # ── ID-70 P1 #1: the session-revocation gate must FAIL CLOSED ──────────
    # An unknown/expired new-style sid (no ActiveSession allow-list row) must be
    # rejected on both the access and refresh paths, never accepted as active.

    def test_id70_p1_minted_login_sid_is_persisted_and_active(self):
        """A fresh login mints an ActiveSession row, so its own tokens pass."""
        user = self._user('id70p1active')
        a = self._login(user.username)
        sid = self._claims(a['refresh'])['sid']
        self.assertTrue(ActiveSession.objects.filter(user=user, sid=sid).exists())
        self.assertEqual(self._userinfo(a['access']).status_code, 200)
        self.assertEqual(self._refresh(a['refresh']).status_code, 200)

    def test_id70_p1_unknown_sid_fails_closed_on_access_and_refresh(self):
        """A sid with no ActiveSession row is not a valid session: both the
        access and refresh paths must reject it (fail closed, not fail open)."""
        user = self._user('id70p1unknown')
        a = self._login(user.username)
        sid = self._claims(a['refresh'])['sid']
        # Simulate a sid that was never issued / already expired: drop the
        # allow-list row while leaving the RevokedSession deny-list empty.
        ActiveSession.objects.filter(user=user, sid=sid).delete()
        self.assertFalse(RevokedSession.objects.filter(user=user, sid=sid).exists())
        # access path: the sid-bearing access token must be rejected
        self.assertGreaterEqual(self._userinfo(a['access']).status_code, 400)
        # refresh path: the sid-bearing refresh token must be rejected
        self.assertGreaterEqual(self._refresh(a['refresh']).status_code, 400)

    def test_id70_p1_logout_drops_active_session_row(self):
        """Logout removes the ActiveSession allow-list row for the family."""
        user = self._user('id70p1drop')
        a = self._login(user.username)
        sid = self._claims(a['refresh'])['sid']
        self.assertTrue(ActiveSession.objects.filter(user=user, sid=sid).exists())
        out = self._logout(a)
        self.assertEqual(out.status_code, 200, out.content)
        self.assertFalse(ActiveSession.objects.filter(user=user, sid=sid).exists())
        self.assertTrue(RevokedSession.objects.filter(user=user, sid=sid).exists())

    # ── ID-70 P1 #2: service/api tokens are sid-scoped, never account-wide ──

    def test_id70_p1_service_token_logout_does_not_revoke_other_sessions(self):
        """Logout of a long-lived service token must revoke ONLY that token's
        family — an unrelated interactive session keeps working (regression for
        the unbounded legacy fallback that called revoke_all_user_tokens)."""
        from identity.views import get_tokens_for_user
        user = self._user('id70p1svc')
        # an independent interactive session for the same user
        interactive = self._login(user.username)
        sid_interactive = self._claims(interactive['refresh'])['sid']
        # mint a long-lived service token (superuser caller, same target)
        self.client.force_authenticate(user=user)
        svc = get_tokens_for_user(user)
        sid_svc = self._claims(svc['refresh'])['sid']
        self.assertNotEqual(sid_svc, sid_interactive)
        self.assertTrue(ActiveSession.objects.filter(user=user, sid=sid_svc).exists())

        out = self._logout(svc)
        self.assertEqual(out.status_code, 200, out.content)
        # service family revoked; interactive family untouched
        self.assertTrue(RevokedSession.objects.filter(user=user, sid=sid_svc).exists())
        self.assertFalse(RevokedSession.objects.filter(user=user, sid=sid_interactive).exists())
        self.assertGreaterEqual(self._refresh(svc['refresh']).status_code, 400)
        self.assertEqual(self._userinfo(interactive['access']).status_code, 200)
        self.assertEqual(self._refresh(interactive['refresh']).status_code, 200)
        # the user-wide access cutoff must NOT have advanced
        profile, _ = UserProfile.objects.get_or_create(user=user)
        self.assertIsNone(profile.access_revoked_before)
