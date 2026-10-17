"""ID-53: list-endpoint hardening — per-caller rate-limit + AllUsersView pagination.

Row-scoping (non-admin cannot enumerate the whole population) landed with ID-52
(InternalUserListView shared-org scoping; AdminUserListView superuser-only;
AllUsersView staff-only). This slice adds the two remaining ID-53 acceptance
items: a per-caller rate-limit (429 over quota, fail-open on limiter backend
error) and enforced pagination on AllUsersView (which returned the full active
population unbounded).
"""
import os
from unittest import mock
from urllib.parse import urlsplit, urlunsplit

import redis
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIRequestFactory, force_authenticate

from identity import list_rate_limit
from identity.views import AllUsersView

User = get_user_model()


def _isolated_redis():
    """Use the gate's real Redis without sharing the application's test DB."""
    configured = urlsplit(os.environ.get('REDIS_URL', 'redis://127.0.0.1:6379/5'))
    client = redis.Redis.from_url(
        urlunsplit(configured._replace(path='/14')),
        decode_responses=True,
    )
    client.flushdb()
    return client


class ListRateLimitUnitTests(TestCase):
    def setUp(self):
        self.redis = _isolated_redis()
        list_rate_limit.set_client(self.redis)

    def tearDown(self):
        list_rate_limit.set_client(None)
        self.redis.flushdb()

    @override_settings(USER_LIST_RATE_LIMIT_PER_WINDOW=3, USER_LIST_RATE_LIMIT_WINDOW_S=60)
    def test_check_allows_up_to_limit_then_denies(self):
        allowed = [list_rate_limit.check("user:1").allowed for _ in range(3)]
        self.assertEqual(allowed, [True, True, True])
        self.assertFalse(list_rate_limit.check("user:1").allowed)  # 4th over the limit=3
        # A different caller has its own window.
        self.assertTrue(list_rate_limit.check("user:2").allowed)

    def test_fail_open_on_backend_error(self):
        class _Broken:
            def register_script(self, *a, **k):
                def _raise(*a, **k):
                    raise RuntimeError("redis down")
                return _raise
        list_rate_limit.set_client(_Broken())
        d = list_rate_limit.check("user:1")
        self.assertTrue(d.allowed)   # fail-OPEN — abuse control never causes an outage
        self.assertEqual(d.count, 0)


class AllUsersViewHardeningTests(TestCase):
    def setUp(self):
        self.redis = _isolated_redis()
        list_rate_limit.set_client(self.redis)
        self.factory = APIRequestFactory()
        self.staff = User.objects.create_user(username="staff", email="staff@x.io", password="p", is_staff=True)
        # A population larger than a page so the cap is observable.
        for i in range(60):
            User.objects.create_user(username=f"u{i}", email=f"u{i}@x.io", password="p")

    def tearDown(self):
        list_rate_limit.set_client(None)
        self.redis.flushdb()

    def _get(self, user, **params):
        req = self.factory.get("/api/auth/users/all/", params)
        force_authenticate(req, user=user)
        return AllUsersView.as_view()(req)

    def test_non_staff_forbidden(self):
        nonstaff = User.objects.create_user(username="ns", email="ns@x.io", password="p")
        resp = self._get(nonstaff)
        self.assertEqual(resp.status_code, 403)

    def test_oversized_limit_is_clamped_to_max_page(self):
        resp = self._get(self.staff, limit=100000)
        self.assertEqual(resp.status_code, 200)
        self.assertLessEqual(len(resp.data["users"]), 100)   # hard max page size
        self.assertEqual(resp.data["limit"], 100)
        self.assertGreaterEqual(resp.data["count"], 61)      # total (staff + 60) unbounded in count only

    def test_default_page_is_bounded(self):
        resp = self._get(self.staff)
        self.assertEqual(resp.status_code, 200)
        self.assertLessEqual(len(resp.data["users"]), 100)
        self.assertIn("limit", resp.data)
        self.assertIn("offset", resp.data)

    @override_settings(USER_LIST_RATE_LIMIT_PER_WINDOW=2, USER_LIST_RATE_LIMIT_WINDOW_S=60)
    def test_rate_limit_returns_429_over_quota(self):
        self.assertEqual(self._get(self.staff).status_code, 200)
        self.assertEqual(self._get(self.staff).status_code, 200)
        resp = self._get(self.staff)   # 3rd call over limit=2
        self.assertEqual(resp.status_code, 429)
        self.assertIn("Retry-After", resp)

    @override_settings(USER_LIST_RATE_LIMIT_ENABLED=False)
    def test_disabled_flag_is_a_noop(self):
        for _ in range(5):
            self.assertEqual(self._get(self.staff).status_code, 200)
