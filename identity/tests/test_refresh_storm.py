"""
Tests for the population-wide refresh-storm signal (ADR-PLAT-002 §5-INV-2).

The view-wiring + attribution-sentinel tests run with no external services.
The sliding-window + edge-debounce integration test exercises the real Lua
script and is skipped when no Redis is reachable (this repo has no CI/Redis
fixture today; PLAT-47 will supply the audit-sink harness).
"""
import time
import unittest

import redis
from django.conf import settings
from django.test import SimpleTestCase, override_settings

from identity import refresh_storm
from identity.refresh_storm import (
    LOCAL_IDP_BUCKET,
    PopulationWideStrategy,
    StormDecision,
    WindowStrategy,
)


def _window_client():
    """Real Redis if reachable, else fakeredis, else None (skip)."""
    try:
        url = getattr(settings, "REFRESH_STORM_REDIS_URL", "redis://localhost:6379/2")
        c = redis.Redis.from_url(url, decode_responses=True, socket_connect_timeout=0.25)
        c.ping()
        return c
    except Exception:  # noqa: BLE001
        pass
    try:
        import fakeredis

        return fakeredis.FakeStrictRedis(decode_responses=True)
    except Exception:  # noqa: BLE001
        return None


class AttributionSentinelTests(SimpleTestCase):
    """The degenerate M-C attribution hook must stay shaped, not pretend."""

    def test_population_strategy_buckets_under_local_idp(self):
        strat = PopulationWideStrategy.__new__(PopulationWideStrategy)
        self.assertEqual(strat.attribution_summary(7), {LOCAL_IDP_BUCKET: 7})

    def test_decision_carries_attribution(self):
        d = StormDecision(
            count=21, threshold=20, window_s=10, should_emit=True,
            attribution_summary={LOCAL_IDP_BUCKET: 21},
        )
        self.assertEqual(d.attribution_summary, {"shizuha-id": 21})


class _FakeStrategy(WindowStrategy):
    """Deterministic strategy for view-wiring tests (no Redis)."""

    def __init__(self, decision):
        self._decision = decision
        self.record_calls = 0

    def record(self, *, now_ms=None):
        self.record_calls += 1
        return self._decision

    def attribution_summary(self, count):
        return {LOCAL_IDP_BUCKET: count}


class ViewWiringTests(SimpleTestCase):
    """The view must emit only on the rising edge and never break auth."""

    def tearDown(self):
        refresh_storm.set_strategy(None)

    def _decision(self, should_emit):
        return StormDecision(
            count=25, threshold=20, window_s=10, should_emit=should_emit,
            attribution_summary={LOCAL_IDP_BUCKET: 25},
        )

    @override_settings(REFRESH_STORM_ENABLED=True)
    def test_emits_on_rising_edge(self):
        from unittest import mock

        refresh_storm.set_strategy(_FakeStrategy(self._decision(should_emit=True)))
        with mock.patch("identity.storm_views.emit_refresh_storm") as emit:
            from identity.storm_views import StormAwareTokenRefreshView

            view = StormAwareTokenRefreshView()
            with mock.patch.object(
                StormAwareTokenRefreshView.__bases__[0], "post",
                return_value=_ok_response(),
            ):
                view.post(_dummy_request())
        emit.assert_called_once()

    @override_settings(REFRESH_STORM_ENABLED=True)
    def test_no_emit_below_edge(self):
        from unittest import mock

        refresh_storm.set_strategy(_FakeStrategy(self._decision(should_emit=False)))
        with mock.patch("identity.storm_views.emit_refresh_storm") as emit:
            from identity.storm_views import StormAwareTokenRefreshView

            view = StormAwareTokenRefreshView()
            with mock.patch.object(
                StormAwareTokenRefreshView.__bases__[0], "post",
                return_value=_ok_response(),
            ):
                view.post(_dummy_request())
        emit.assert_not_called()

    @override_settings(REFRESH_STORM_ENABLED=True)
    def test_detection_failure_is_non_fatal(self):
        from unittest import mock

        boom = _FakeStrategy(self._decision(should_emit=True))
        boom.record = mock.Mock(side_effect=RuntimeError("redis down"))
        refresh_storm.set_strategy(boom)
        from identity.storm_views import StormAwareTokenRefreshView

        view = StormAwareTokenRefreshView()
        with mock.patch.object(
            StormAwareTokenRefreshView.__bases__[0], "post",
            return_value=_ok_response(),
        ):
            resp = view.post(_dummy_request())
        self.assertEqual(resp.status_code, 200)


@unittest.skipUnless(_window_client() is not None, "no Redis/fakeredis for window test")
class SlidingWindowIntegrationTests(SimpleTestCase):
    """Exercise the real Lua sliding-window + rising-edge debounce."""

    def setUp(self):
        self.client = _window_client()
        self.client.delete("refresh_storm:events", "refresh_storm:active")
        self.strat = PopulationWideStrategy(self.client, threshold=5, window_s=2)

    def tearDown(self):
        self.client.delete("refresh_storm:events", "refresh_storm:active")

    def test_emits_once_per_window_when_sustained(self):
        emits = [self.strat.record().should_emit for _ in range(10)]
        self.assertEqual(emits.count(True), 1)
        self.assertTrue(any(emits))
        # The single emit must be at the crossing (the 5th event), not before.
        self.assertEqual(emits.index(True), 4)

    def test_window_expiry_drops_stale_events(self):
        for _ in range(4):
            self.strat.record()
        time.sleep(2.1)
        d = self.strat.record()  # window cleared -> this is event #1 again
        self.assertEqual(d.count, 1)
        self.assertFalse(d.should_emit)

    def test_single_emit_across_sustained_multiwindow(self):
        # AC2's actual predicate: load sustained ABOVE threshold for longer than
        # one window must yield EXACTLY ONE storm event. The previous per-window
        # active-flag TTL expired every window and re-fired (~one event/window);
        # the rising-edge latch must hold the single emit across all windows.
        strat = PopulationWideStrategy(self.client, threshold=5, window_s=1)
        emits = 0
        deadline = time.time() + 3.0  # ~3 windows of sustained over-threshold load
        while time.time() < deadline:
            if strat.record().should_emit:
                emits += 1
            time.sleep(0.05)  # ~20 records/s -> trailing 1s window stays well above 5
        self.assertEqual(emits, 1)

    def test_recrossing_re_arms_and_emits_again(self):
        # cross -> drop below -> cross again must produce TWO emits. Driven with
        # explicit timestamps so the second crossing lands inside the old gate's
        # real-time TTL: the previous TTL-gate suppressed it (one emit); the
        # below-threshold DEL re-arms the detector so it emits twice.
        strat = PopulationWideStrategy(self.client, threshold=5, window_s=2)
        first = [strat.record(now_ms=t).should_emit for t in range(5)]
        self.assertEqual(first, [False, False, False, False, True])
        # Jump past the window so the first burst ages out; this record is below
        # threshold -> the latch is DELed (re-armed).
        drop = strat.record(now_ms=10_000)
        self.assertFalse(drop.should_emit)
        self.assertEqual(drop.count, 1)
        # Second genuine crossing -> emits again.
        second = [strat.record(now_ms=10_000 + t).should_emit for t in range(1, 5)]
        self.assertEqual(second, [False, False, False, True])


class StrategyDispatchTests(SimpleTestCase):
    """AC5: the M-C strategy swap is a config change (a setting), not code."""

    def tearDown(self):
        refresh_storm.set_strategy(None)
        refresh_storm._STRATEGY_REGISTRY.pop("test-only", None)

    def test_default_is_population_wide(self):
        refresh_storm.set_strategy(None)
        self.assertIsInstance(refresh_storm.get_strategy(), PopulationWideStrategy)

    @override_settings(REFRESH_STORM_WINDOW_STRATEGY="test-only")
    def test_setting_selects_registered_strategy(self):
        refresh_storm.set_strategy(None)

        class _Registered(PopulationWideStrategy):
            pass

        refresh_storm._STRATEGY_REGISTRY["test-only"] = _Registered
        self.assertIsInstance(refresh_storm.get_strategy(), _Registered)

    @override_settings(REFRESH_STORM_WINDOW_STRATEGY="does-not-exist")
    def test_unknown_strategy_raises(self):
        from django.core.exceptions import ImproperlyConfigured

        refresh_storm.set_strategy(None)
        with self.assertRaises(ImproperlyConfigured):
            refresh_storm.get_strategy()


def _ok_response():
    from rest_framework.response import Response

    return Response({"access": "x"}, status=200)


def _dummy_request():
    from unittest import mock

    return mock.Mock()
