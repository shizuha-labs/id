"""ID-41 (HLD ID-3 §6 P4 / gap L-6): token-epoch revocation on deactivate/delete.

When the ID-32 lifecycle FSM lands a ``deactivated`` or soft-``deleted``
transition, ``transition_user`` must reuse ID-1's ``revoke_all_user_tokens`` so
every access/refresh token and live session minted before the transition stops
validating — atomically with the state change. Reactivation keeps the cutoff, so
pre-deactivation tokens stay dead while fresh logins mint tokens that validate.

Mechanism note (aoi arbitration 2026-06-20): revocation is the
``UserProfile.access_revoked_before`` cutoff + jti/blacklist — there is NO
``token_version`` field. "Advancing the epoch" == bumping that cutoff.

Invariant (PLAT-1254): no token/session predating a deactivate/delete
transition validates. Probe: id_users_invalid_lifecycle{check=
"deactivated_without_revocation"} + id_lifecycle_revocation_total{outcome} route
a failure to the on-call lead via the Alertmanager/critical-alert-notifier path.
"""
from datetime import datetime, timedelta, timezone as dt_timezone
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework_simplejwt.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import AccessToken

from identity.authentication import _enforce_user_revocation
from identity.lifecycle import IllegalLifecycleTransition, LifecycleState, transition_user
from identity.models import PushToken, UserProfile

User = get_user_model()


def _user(username, *, state=LifecycleState.ACTIVE, is_active=True):
    user = User.objects.create_user(
        username=username, email=f'{username}@shizuha.com', password='Pass123!x',
        is_active=is_active,
    )
    profile = user.profile
    profile.lifecycle_state = state
    profile.approval_status = 'approved' if state == LifecycleState.ACTIVE else profile.approval_status
    profile.save(update_fields=['lifecycle_state', 'approval_status'])
    return user


def _iat(access_token):
    return access_token['iat']


class DeactivateDeleteRevokesTests(TestCase):
    """Deactivate / soft-delete advance the cutoff and kill prior sessions."""

    def test_deactivate_advances_cutoff_and_rejects_prior_token(self):
        user = _user('alice')
        # A token minted while active, before the transition.
        prior = AccessToken.for_user(user)
        prior_iat = _iat(prior)
        before = timezone.now()

        UserProfile.objects.filter(user=user).update(access_revoked_before=None)
        transition_user(user, LifecycleState.DEACTIVATED, reason='offboard')

        profile = UserProfile.objects.get(user=user)
        self.assertIsNotNone(profile.access_revoked_before, 'cutoff must be set on deactivate')
        self.assertGreaterEqual(profile.access_revoked_before, before)
        # The pre-deactivation token (iat <= cutoff) is now rejected.
        with self.assertRaises(AuthenticationFailed):
            _enforce_user_revocation(profile.access_revoked_before, prior_iat, AuthenticationFailed)

    def test_soft_delete_advances_cutoff(self):
        user = _user('bob')
        UserProfile.objects.filter(user=user).update(access_revoked_before=None)
        before = timezone.now()

        transition_user(user, LifecycleState.DELETED, reason='delete')

        profile = UserProfile.objects.get(user=user)
        self.assertIsNotNone(profile.access_revoked_before, 'cutoff must be set on soft-delete')
        self.assertGreaterEqual(profile.access_revoked_before, before)

    def test_deactivate_purges_push_tokens(self):
        """End-to-end proof revoke_all_user_tokens actually ran (not just cutoff)."""
        user = _user('carol')
        PushToken.objects.create(
            user=user, token='ExponentPushToken[carol-dev]', device_id='carol-dev',
            platform='android', is_active=True,
        )
        transition_user(user, LifecycleState.DEACTIVATED, reason='offboard')
        self.assertEqual(PushToken.objects.filter(user=user, is_active=True).count(), 0)

    def test_reactivation_keeps_cutoff_old_dead_new_valid(self):
        user = _user('dave')
        UserProfile.objects.filter(user=user).update(access_revoked_before=None)
        transition_user(user, LifecycleState.DEACTIVATED, reason='offboard')
        cutoff = UserProfile.objects.get(user=user).access_revoked_before
        self.assertIsNotNone(cutoff)

        transition_user(user, LifecycleState.ACTIVE, reason='rehire')
        after = UserProfile.objects.get(user=user)
        # Reactivation must NOT lower the cutoff — old tokens stay dead.
        self.assertEqual(after.access_revoked_before, cutoff)
        self.assertTrue(after.user.is_active)

        # Deterministic (avoids 1-second iat granularity): a pre-deactivation
        # token (iat before cutoff) stays rejected; a token a fresh login mints
        # after the cutoff validates.
        old_iat = int((cutoff - timedelta(seconds=1)).timestamp())
        new_iat = int((cutoff + timedelta(seconds=1)).timestamp())
        with self.assertRaises(AuthenticationFailed):
            _enforce_user_revocation(after.access_revoked_before, old_iat, AuthenticationFailed)
        # No raise → the post-reactivation token is accepted.
        _enforce_user_revocation(after.access_revoked_before, new_iat, AuthenticationFailed)


class RevocationWiringTests(TestCase):
    """Only removal transitions revoke; atomicity holds both directions."""

    def test_approve_does_not_revoke(self):
        user = _user('erin', state=LifecycleState.PENDING, is_active=False)
        with mock.patch('identity.views.revoke_all_user_tokens') as revoke:
            transition_user(user, LifecycleState.ACTIVE, reason='approve')
        revoke.assert_not_called()

    def test_reactivate_does_not_revoke(self):
        user = _user('frank', state=LifecycleState.DEACTIVATED, is_active=False)
        with mock.patch('identity.views.revoke_all_user_tokens') as revoke:
            transition_user(user, LifecycleState.ACTIVE, reason='rehire')
        revoke.assert_not_called()

    def test_illegal_transition_does_not_revoke(self):
        user = _user('grace', state=LifecycleState.DELETED, is_active=False)
        with mock.patch('identity.views.revoke_all_user_tokens') as revoke:
            with self.assertRaises(IllegalLifecycleTransition):
                transition_user(user, LifecycleState.ACTIVE, reason='illegal')
        revoke.assert_not_called()

    def test_revocation_failure_aborts_transition_fail_closed(self):
        user = _user('heidi')
        with mock.patch('identity.views.revoke_all_user_tokens', side_effect=RuntimeError('redis down')), \
                mock.patch('identity.invariants.record_lifecycle_revocation') as metric:
            with self.assertRaises(RuntimeError):
                transition_user(user, LifecycleState.DEACTIVATED, reason='offboard')

        # Fail-closed: state rolled back — the user is NOT deactivated.
        user.refresh_from_db()
        profile = UserProfile.objects.get(user=user)
        self.assertTrue(user.is_active)
        self.assertEqual(profile.lifecycle_state, LifecycleState.ACTIVE)
        # Fail-loud: the failure metric was recorded before the abort.
        metric.assert_any_call('failure')

    def test_success_metric_recorded_on_commit(self):
        user = _user('ivan')
        with mock.patch('identity.invariants.record_lifecycle_revocation') as metric:
            with self.captureOnCommitCallbacks(execute=True):
                transition_user(user, LifecycleState.DEACTIVATED, reason='offboard')
        metric.assert_any_call('success')


class RevocationMetricTests(TestCase):
    """The PLAT-1254 probe: counter write-hook + read-side invariant gauge."""

    class _FakeRedis:
        def __init__(self):
            self.calls = []

        def incr(self, key):
            self.calls.append(key)

        def mget(self, keys):
            return [None] * len(keys)

    def test_record_lifecycle_revocation_increments_and_validates_outcome(self):
        from identity.invariants import record_lifecycle_revocation

        r = self._FakeRedis()
        record_lifecycle_revocation('success', redis_client=r)
        record_lifecycle_revocation('failure', redis_client=r)
        record_lifecycle_revocation('bogus', redis_client=r)  # unknown outcome ignored
        self.assertEqual(r.calls, [
            'id:metrics:lifecycle_revocation:success',
            'id:metrics:lifecycle_revocation:failure',
        ])

    def test_deactivated_without_revocation_gauge(self):
        from identity.invariants import collect_id_invariant_metrics

        stub = self._FakeRedis()
        # Drift: a deactivated profile with no cutoff = a live-session leak.
        leak = _user('judy', state=LifecycleState.DEACTIVATED, is_active=False)
        UserProfile.objects.filter(user=leak).update(access_revoked_before=None)
        metrics = collect_id_invariant_metrics(redis_client=stub)
        self.assertEqual(metrics.deactivated_without_revocation, 1)

        # Once revoked, the drift clears.
        UserProfile.objects.filter(user=leak).update(access_revoked_before=timezone.now())
        metrics = collect_id_invariant_metrics(redis_client=stub)
        self.assertEqual(metrics.deactivated_without_revocation, 0)

    def test_render_includes_lifecycle_revocation_series(self):
        from identity.invariants import IdInvariantMetrics, render_prometheus_metrics

        text = render_prometheus_metrics(IdInvariantMetrics(
            approved_missing_timestamp=0, active_not_approved=0, grants_disabled=0,
            deactivated_without_revocation=2,
            lifecycle_revocations={'success': 5, 'failure': 1},
        ))
        self.assertIn('id_users_invalid_lifecycle{check="deactivated_without_revocation"} 2', text)
        self.assertIn('id_lifecycle_revocation_total{outcome="success"} 5', text)
        self.assertIn('id_lifecycle_revocation_total{outcome="failure"} 1', text)
