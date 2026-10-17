"""PLAT-1278: Shizuha ID invariant metrics tests."""
import fakeredis
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from identity.invariants import (
    collect_id_invariant_metrics,
    record_token_event,
    render_prometheus_metrics,
)
from identity.models import Tool

User = get_user_model()


def _fake_redis():
    return fakeredis.FakeStrictRedis(decode_responses=True)


class IdInvariantMetricsTests(TestCase):
    def _user(self, username, *, is_active=True, approval_status='approved', approved_at=timezone.now):
        user = User.objects.create_user(
            username=username, email=f'{username}@test.local', password='x', is_active=is_active
        )
        profile = user.profile
        profile.approval_status = approval_status
        profile.approved_at = approved_at() if callable(approved_at) else approved_at
        profile.save(update_fields=['approval_status', 'approved_at'])
        return user

    def test_clean_state_reports_zero(self):
        self._user('ok')
        metrics = collect_id_invariant_metrics(redis_client=_fake_redis())
        self.assertEqual(metrics.approved_missing_timestamp, 0)
        self.assertEqual(metrics.active_not_approved, 0)
        self.assertEqual(metrics.grants_disabled, 0)
        self.assertEqual(metrics.probe_errors, 0)

    def test_approved_without_timestamp_is_flagged(self):
        self._user('drifted', approved_at=lambda: None)
        metrics = collect_id_invariant_metrics(redis_client=_fake_redis())
        self.assertEqual(metrics.approved_missing_timestamp, 1)

    def test_active_but_not_approved_is_flagged(self):
        self._user('sneaky', approval_status='pending')
        self._user('denied-active', approval_status='denied')
        metrics = collect_id_invariant_metrics(redis_client=_fake_redis())
        self.assertEqual(metrics.active_not_approved, 2)

    def test_inactive_pending_user_is_not_flagged(self):
        self._user('waiting', is_active=False, approval_status='pending')
        metrics = collect_id_invariant_metrics(redis_client=_fake_redis())
        self.assertEqual(metrics.active_not_approved, 0)

    def test_grant_referencing_disabled_tool_is_flagged(self):
        user = self._user('grantee')
        enabled = Tool.objects.create(slug='alive', display_name='Alive', is_active=True)
        disabled = Tool.objects.create(slug='dead', display_name='Dead', is_active=False)
        user.profile.enabled_tools.add(enabled, disabled)
        metrics = collect_id_invariant_metrics(redis_client=_fake_redis())
        self.assertEqual(metrics.grants_disabled, 1)

    def test_token_event_counters_round_trip(self):
        r = _fake_redis()
        record_token_event('password', 'failure', redis_client=r)
        record_token_event('password', 'failure', redis_client=r)
        record_token_event('refresh', 'success', redis_client=r)
        metrics = collect_id_invariant_metrics(redis_client=r)
        self.assertEqual(metrics.token_events[('password', 'failure')], 2)
        self.assertEqual(metrics.token_events[('refresh', 'success')], 1)
        self.assertEqual(metrics.token_events[('twofa', 'failure')], 0)

    def test_redis_down_sets_probe_error_but_keeps_db_gauges(self):
        class _Broken:
            def mget(self, keys):
                raise ConnectionError('down')

        self._user('drifted', approved_at=lambda: None)
        metrics = collect_id_invariant_metrics(redis_client=_Broken())
        self.assertEqual(metrics.approved_missing_timestamp, 1)
        self.assertEqual(metrics.probe_errors, 1)

    def test_render_exposition_format(self):
        r = _fake_redis()
        record_token_event('twofa', 'failure', redis_client=r)
        body = render_prometheus_metrics(collect_id_invariant_metrics(redis_client=r))
        self.assertIn('id_users_invalid_lifecycle{check="approved_missing_timestamp"} 0', body)
        self.assertIn('id_service_grants_disabled_total 0', body)
        self.assertIn('id_token_event_total{stage="twofa",outcome="failure"} 1', body)
        self.assertIn('id_invariant_probe_errors 0', body)
        self.assertTrue(body.endswith('\n'))

    def test_metrics_endpoint_serves_exposition(self):
        resp = self.client.get('/api/metrics/')
        self.assertEqual(resp.status_code, 200)
        self.assertIn('text/plain', resp['Content-Type'])
        self.assertIn(b'id_users_invalid_lifecycle', resp.content)
