"""ID-13: user-level access-token revocation cutoff.

Logout / password-change bump ``UserProfile.access_revoked_before``; an access
token whose ``iat`` is <= that cutoff is rejected on the next request, on BOTH
the HS256 (platform-default) and RS256 paths, and FAIL-CLOSED (a cutoff with a
missing/invalid iat rejects, never allows through).
"""
from datetime import datetime, timedelta, timezone as dt_timezone
from types import SimpleNamespace
from unittest import mock

from django.core.cache import cache
from django.test import SimpleTestCase, TestCase
from rest_framework.exceptions import AuthenticationFailed as DRFAuthFailed
from rest_framework_simplejwt.exceptions import AuthenticationFailed

from identity.authentication import (
    OAuthClientRevocationJWTAuthentication,
    _access_cutoff_cache_key,
    _enforce_user_revocation,
    _enforce_session_revocation,
    _session_is_revoked,
    _session_revocation_cache_key,
    _user_access_cutoff,
    prime_session_revocation_cache,
    prime_user_access_cutoff_cache,
)

CUTOFF = datetime(2026, 6, 26, 12, 0, tzinfo=dt_timezone.utc)


def _ts(dt):
    return int(dt.timestamp())


class EnforceUserRevocationTests(SimpleTestCase):
    def test_no_cutoff_is_noop(self):
        _enforce_user_revocation(None, _ts(CUTOFF), AuthenticationFailed)  # no raise

    def test_token_before_cutoff_rejected(self):
        with self.assertRaises(AuthenticationFailed):
            _enforce_user_revocation(CUTOFF, _ts(CUTOFF - timedelta(seconds=1)), AuthenticationFailed)

    def test_token_at_cutoff_rejected(self):
        with self.assertRaises(AuthenticationFailed):
            _enforce_user_revocation(CUTOFF, _ts(CUTOFF), AuthenticationFailed)

    def test_token_after_cutoff_allowed(self):
        _enforce_user_revocation(CUTOFF, _ts(CUTOFF + timedelta(seconds=1)), AuthenticationFailed)

    def test_failclosed_missing_iat(self):
        with self.assertRaises(AuthenticationFailed):
            _enforce_user_revocation(CUTOFF, None, AuthenticationFailed)

    def test_failclosed_unparseable_iat(self):
        with self.assertRaises(AuthenticationFailed):
            _enforce_user_revocation(CUTOFF, 'not-a-number', AuthenticationFailed)

    def test_uses_caller_exception_class_for_rs256_path(self):
        # RS256 path raises DRF's AuthenticationFailed (→ 401).
        with self.assertRaises(DRFAuthFailed):
            _enforce_user_revocation(CUTOFF, _ts(CUTOFF), DRFAuthFailed)


class UserAccessCutoffLookupTests(SimpleTestCase):
    def test_none_user_id_returns_none(self):
        self.assertIsNone(_user_access_cutoff(None))

    def setUp(self):
        cache.clear()

    def tearDown(self):
        cache.clear()

    def _mock_profile_objects(self, cutoff):
        objs = mock.patch('identity.models.UserProfile.objects').start()
        objs.filter.return_value.values_list.return_value.first.return_value = cutoff
        self.addCleanup(mock.patch.stopall)
        return objs

    def test_returns_profile_cutoff(self):
        objs = self._mock_profile_objects(CUTOFF)
        self.assertEqual(_user_access_cutoff(42), CUTOFF)
        objs.filter.assert_called_once_with(user_id=42)

    def test_cache_miss_then_hit_avoids_second_db_read(self):
        # First call: cache miss -> DB read (and populate). Second call: cache hit,
        # NO further DB read.
        objs = self._mock_profile_objects(CUTOFF)
        self.assertEqual(_user_access_cutoff(99), CUTOFF)
        self.assertEqual(_user_access_cutoff(99), CUTOFF)
        objs.filter.assert_called_once()  # DB hit exactly once across both calls

    def test_no_cutoff_is_cached_via_sentinel(self):
        # The common "no cutoff" answer is cached too, so a normal user doesn't hit
        # the DB on every request. Second call must not re-query.
        objs = self._mock_profile_objects(None)
        self.assertIsNone(_user_access_cutoff(7))
        self.assertIsNone(_user_access_cutoff(7))
        objs.filter.assert_called_once()

    def test_cache_backend_down_falls_back_to_db(self):
        # If the cache backend errors on get, fall through to the authoritative DB
        # (fail-closed: a DB error would propagate as a 401, never allow-through).
        objs = self._mock_profile_objects(CUTOFF)
        with mock.patch('identity.authentication.cache.get', side_effect=RuntimeError('cache down')), \
             mock.patch('identity.authentication.cache.set', side_effect=RuntimeError('cache down')):
            self.assertEqual(_user_access_cutoff(33), CUTOFF)
        objs.filter.assert_called_once_with(user_id=33)

    def test_write_through_prime_is_read_without_db(self):
        # prime_user_access_cutoff_cache (called by the revoke path) makes the new
        # cutoff visible immediately, with no DB read on the next check.
        objs = self._mock_profile_objects(None)  # DB would say "no cutoff"...
        prime_user_access_cutoff_cache(55, CUTOFF)  # ...but revoke just primed it
        self.assertEqual(_user_access_cutoff(55), CUTOFF)
        objs.filter.assert_not_called()  # served entirely from the primed cache
        self.assertEqual(cache.get(_access_cutoff_cache_key(55)), CUTOFF)


class SessionRevocationLookupTests(SimpleTestCase):
    """ID-70: positive-cache optimisation with authoritative DB fallback."""

    def setUp(self):
        cache.clear()

    def tearDown(self):
        cache.clear()

    def _mock_sessions(self, revoked, issued=True):
        objects = mock.patch('identity.models.RevokedSession.objects').start()
        objects.filter.return_value.exists.return_value = revoked
        # ID-70 P1 #1: the gate also consults the ActiveSession allow-list and
        # fails closed on an unknown sid. Default `issued=True` keeps the
        # "active, not revoked" path exercised without a live DB.
        active = mock.patch('identity.models.ActiveSession.objects').start()
        active.filter.return_value.exists.return_value = issued
        self.addCleanup(mock.patch.stopall)
        return objects

    def test_missing_sid_is_legacy_noop(self):
        objects = self._mock_sessions(True)
        self.assertFalse(_session_is_revoked(7, ''))
        objects.filter.assert_not_called()

    def test_positive_db_result_is_cached(self):
        objects = self._mock_sessions(True)
        self.assertTrue(_session_is_revoked(7, 'sid-a'))
        self.assertTrue(_session_is_revoked(7, 'sid-a'))
        objects.filter.assert_called_once_with(user_id=7, sid='sid-a')
        self.assertIs(cache.get(_session_revocation_cache_key(7, 'sid-a')), True)

    def test_negative_result_is_not_cached(self):
        # An issued-but-not-revoked sid is active; that negative answer is NOT
        # cached so a later logout on another worker is immediately visible.
        objects = self._mock_sessions(False, issued=True)
        self.assertFalse(_session_is_revoked(7, 'sid-b'))
        self.assertFalse(_session_is_revoked(7, 'sid-b'))
        self.assertEqual(objects.filter.call_count, 2)

    def test_unknown_sid_fails_closed(self):
        # ID-70 P1 #1: a sid with no ActiveSession allow-list row is not a valid
        # session — the gate returns revoked even with an empty deny-list.
        objects = self._mock_sessions(False, issued=False)
        self.assertTrue(_session_is_revoked(7, 'sid-unknown'))

    def test_cache_down_falls_back_to_db(self):
        objects = self._mock_sessions(True)
        with mock.patch('identity.authentication.cache.get', side_effect=RuntimeError('cache down')), \
             mock.patch('identity.authentication.cache.set', side_effect=RuntimeError('cache down')):
            self.assertTrue(_session_is_revoked(8, 'sid-c'))
        objects.filter.assert_called_once_with(user_id=8, sid='sid-c')

    def test_db_error_propagates_fail_closed(self):
        objects = mock.patch('identity.models.RevokedSession.objects').start()
        objects.filter.side_effect = RuntimeError('db down')
        self.addCleanup(mock.patch.stopall)
        with self.assertRaises(RuntimeError):
            _session_is_revoked(9, 'sid-d')

    def test_enforcement_raises_for_revoked_sid(self):
        with mock.patch('identity.authentication._session_is_revoked', return_value=True):
            with self.assertRaises(AuthenticationFailed):
                _enforce_session_revocation(9, 'sid-e', AuthenticationFailed)

    def test_write_through_prime_is_read_without_db(self):
        objects = self._mock_sessions(False)
        prime_session_revocation_cache(10, 'sid-f')
        self.assertTrue(_session_is_revoked(10, 'sid-f'))
        objects.filter.assert_not_called()


class HS256GetValidatedTokenCutoffTests(SimpleTestCase):
    """The platform-default authenticator enforces the user cutoff for any
    access token carrying a user_id, with or without a client_id."""

    def _run(self, claims, cutoff):
        token = SimpleNamespace(get=claims.get)
        with mock.patch(
            'rest_framework_simplejwt.authentication.JWTAuthentication.get_validated_token',
            return_value=token,
        ), mock.patch(
            'identity.authentication._user_access_cutoff', return_value=cutoff,
        ):
            return OAuthClientRevocationJWTAuthentication().get_validated_token(b'raw')

    def test_pre_cutoff_user_token_rejected(self):
        claims = {'user_id': 7, 'iat': _ts(CUTOFF - timedelta(seconds=5))}
        with self.assertRaises(AuthenticationFailed):
            self._run(claims, CUTOFF)

    def test_post_cutoff_user_token_allowed(self):
        claims = {'user_id': 7, 'iat': _ts(CUTOFF + timedelta(seconds=5))}
        self.assertIsNotNone(self._run(claims, CUTOFF))

    def test_normal_user_no_cutoff_unaffected(self):
        claims = {'user_id': 7, 'iat': _ts(datetime.now(dt_timezone.utc))}
        self.assertIsNotNone(self._run(claims, None))

    def test_failclosed_pre_cutoff_even_without_client_id(self):
        # No client_id (regular user token) — the gap ID-13 closes.
        claims = {'user_id': 7, 'iat': _ts(CUTOFF - timedelta(days=1))}
        with self.assertRaises(AuthenticationFailed):
            self._run(claims, CUTOFF)


class RevokeAllUserTokensBumpsCutoffTests(TestCase):
    def setUp(self):
        cache.clear()

    def tearDown(self):
        cache.clear()

    def test_revoke_bumps_user_access_cutoff(self):
        from identity import views
        user = SimpleNamespace(id=5)
        profile = SimpleNamespace(access_revoked_before=None, save=mock.Mock())
        with mock.patch('identity.models.UserProfile.objects') as objs, \
             mock.patch('identity.models.PushToken.objects') as pushes:
            objs.get_or_create.return_value = (profile, False)
            pushes.filter.return_value.update.return_value = 0
            # The refresh-token blacklist blocks below are best-effort try/except;
            # let them no-op on the SimpleNamespace user — we assert only the bump.
            views.revoke_all_user_tokens(user)
        self.assertIsNotNone(profile.access_revoked_before)
        # PLAT-5996: the revoke also increments token_version in the same
        # transaction, so the save carries both fields.
        profile.save.assert_called_once_with(
            update_fields=['access_revoked_before', 'token_version']
        )
        # write-through: the new cutoff is in the cache, served without a DB read.
        self.assertEqual(
            cache.get(_access_cutoff_cache_key(5)), profile.access_revoked_before
        )

    def test_cutoff_bump_failure_propagates_fail_closed(self):
        # FAIL-CLOSED (review: ichi): if the access-cutoff bump fails, the revoke
        # MUST raise — never silently report success while access tokens live on.
        from identity import views
        user = SimpleNamespace(id=8)
        with mock.patch('identity.models.UserProfile.objects') as objs, \
             mock.patch('identity.models.PushToken.objects'):
            objs.get_or_create.side_effect = RuntimeError('db down')
            with self.assertRaises(RuntimeError):
                views.revoke_all_user_tokens(user)
