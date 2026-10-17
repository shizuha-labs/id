"""Tests for the per-tenant rate-limit middleware (PLAT-1331 Part B).

Exercises the real Lua sliding-window against fakeredis[lua] (a dev dep), so
these run with no external Redis. Covers: allow under limit, 429 over limit,
fail-open when Redis is unavailable, and per-tenant isolation.
"""
from unittest import mock

from django.http import HttpResponse
from django.test import SimpleTestCase, override_settings

from identity import tenant_rate_limit as trl
from identity.tenant_rate_limit import (
    RateDecision,
    TenantRateLimitMiddleware,
    resolve_tenant_key,
)


def _fakeredis():
    import fakeredis
    return fakeredis.FakeStrictRedis(decode_responses=True)


class _Req:
    """Minimal request stand-in (META + user/auth claims) for middleware/key tests."""
    def __init__(self, org=None, user_pk=None, authed=True, memberships=None):
        self.META = {}
        if org is not None:
            self.META["HTTP_X_ORGANIZATION_ID"] = str(org)
        if memberships is None and org is not None:
            memberships = {str(org): "member"}
        self.user = mock.Mock(is_authenticated=authed, pk=user_pk)
        self.user.organization_memberships = memberships or {}
        self.auth = {"organization_memberships": memberships or {}}


@override_settings(TENANT_RATE_LIMIT_RPM=3, TENANT_RATE_LIMIT_WINDOW_S=60)
class LimiterCheckTests(SimpleTestCase):
    def setUp(self):
        trl.set_client(_fakeredis())
        self.addCleanup(trl.reset_client)

    def test_allows_up_to_limit_then_blocks(self):
        results = [trl.check("org:1", now_ms=1000 + i).allowed for i in range(5)]
        # limit=3 → first 3 allowed, 4th/5th blocked (count 4,5 > 3)
        self.assertEqual(results, [True, True, True, False, False])

    def test_window_evicts_old_events(self):
        for i in range(3):
            trl.check("org:9", now_ms=1000 + i)
        self.assertFalse(trl.check("org:9", now_ms=1003).allowed)  # 4th within window
        # a request > window later sees the old ones evicted → allowed again
        later = 1000 + 60_000 + 1
        self.assertTrue(trl.check("org:9", now_ms=later).allowed)

    def test_per_tenant_isolation(self):
        for i in range(3):
            self.assertTrue(trl.check("org:A", now_ms=2000 + i).allowed)
        self.assertFalse(trl.check("org:A", now_ms=2004).allowed)  # A exhausted
        # B has its own window — unaffected by A saturating its quota
        self.assertTrue(trl.check("org:B", now_ms=2005).allowed)

    def test_fail_open_on_redis_error(self):
        boom = mock.Mock(side_effect=RuntimeError("redis down"))
        with mock.patch.object(trl, "_get_client", boom):
            trl.reset_client()
            d = trl.check("org:1")
        self.assertTrue(d.allowed)   # availability control must fail OPEN
        self.assertEqual(d.count, 0)


class TenantKeyResolutionTests(SimpleTestCase):
    def test_org_header_takes_precedence_for_verified_member(self):
        self.assertEqual(resolve_tenant_key(_Req(org=7, user_pk=42, memberships={"7": "admin"})), "org:7")

    def test_foreign_org_header_falls_back_to_user_bucket(self):
        self.assertEqual(resolve_tenant_key(_Req(org=7, user_pk=42, memberships={"8": "member"})), "user:42")

    def test_falls_back_to_user(self):
        self.assertEqual(resolve_tenant_key(_Req(user_pk=42)), "user:42")

    def test_unauthenticated_is_not_metered(self):
        self.assertIsNone(resolve_tenant_key(_Req(authed=False)))

    def test_bad_org_header_falls_back_to_user(self):
        self.assertEqual(resolve_tenant_key(_Req(org="not-an-int", user_pk=5)), "user:5")


@override_settings(TENANT_RATE_LIMIT_RPM=2, TENANT_RATE_LIMIT_WINDOW_S=60)
class MiddlewareTests(SimpleTestCase):
    def setUp(self):
        trl.set_client(_fakeredis())
        self.addCleanup(trl.reset_client)

    def _mw(self):
        return TenantRateLimitMiddleware(lambda request: HttpResponse("ok"))

    @override_settings(TENANT_RATE_LIMIT_ENABLED=False)
    def test_disabled_is_passthrough(self):
        mw = self._mw()
        for _ in range(10):
            self.assertEqual(mw(_Req(org=1)).status_code, 200)

    @override_settings(TENANT_RATE_LIMIT_ENABLED=True)
    def test_enabled_returns_429_over_limit(self):
        mw = self._mw()
        codes = [mw(_Req(org=1)).status_code for _ in range(4)]
        self.assertEqual(codes[:2], [200, 200])   # limit=2
        self.assertEqual(codes[2], 429)
        self.assertEqual(codes[3], 429)

    @override_settings(TENANT_RATE_LIMIT_ENABLED=True)
    def test_unauthenticated_request_is_passthrough(self):
        mw = self._mw()
        for _ in range(10):
            self.assertEqual(mw(_Req(authed=False)).status_code, 200)

    @override_settings(TENANT_RATE_LIMIT_ENABLED=True)
    def test_429_carries_retry_after(self):
        mw = self._mw()
        for _ in range(2):
            mw(_Req(org=5))
        resp = mw(_Req(org=5))
        self.assertEqual(resp.status_code, 429)
        self.assertEqual(resp["Retry-After"], "60")
