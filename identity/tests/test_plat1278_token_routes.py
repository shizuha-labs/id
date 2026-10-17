"""
PLAT-1278 route-level regressions (ren's Request-Changes on ID #55).

The token-outcome counter must be wired to the ACTUAL routed views, not the
unrouted identity.views.TokenRefreshView. These tests hit the real routes
(`/api/auth/refresh/` -> StormAwareTokenRefreshView, `/api/auth/service-token/`
-> ServiceTokenView) and assert the Redis-backed counters change for success
AND failure. A fake Redis is injected via identity.invariants._redis_client so
no live Redis is required.
"""
from unittest import mock

import fakeredis
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase, APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from identity import invariants
from identity.invariants import _COUNTER_KEY

User = get_user_model()


class TokenRouteMetricsTests(APITestCase):
    def setUp(self):
        self.fake = fakeredis.FakeStrictRedis(decode_responses=True)
        self._patch = mock.patch.object(invariants, '_redis_client', return_value=self.fake)
        self._patch.start()
        self.addCleanup(self._patch.stop)
        self.client = APIClient()
        # Success-counter tests need an authoritative Admin projection. Keep
        # the actual routed mint/refresh and counter implementation exercised.
        projection = mock.patch('identity.views._fetch_membership_projection',
                                return_value=({}, [], {}))
        projection.start()
        self.addCleanup(projection.stop)

    def _count(self, stage, outcome):
        raw = self.fake.get(_COUNTER_KEY.format(stage=stage, outcome=outcome))
        return int(raw) if raw else 0

    # ---- refresh (StormAwareTokenRefreshView) ----
    def test_refresh_success_increments_refresh_success(self):
        user = User.objects.create_user(username='r1', email='r1@example.com', password='pw')
        refresh = str(RefreshToken.for_user(user))
        resp = self.client.post('/api/auth/refresh/', {'refresh': refresh}, format='json')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self._count('refresh', 'success'), 1)
        self.assertEqual(self._count('refresh', 'failure'), 0)

    def test_refresh_invalid_token_increments_refresh_failure(self):
        self.client.raise_request_exception = False
        resp = self.client.post('/api/auth/refresh/', {'refresh': 'not-a-real-token'}, format='json')
        self.assertGreaterEqual(resp.status_code, 400)
        self.assertEqual(self._count('refresh', 'failure'), 1)
        self.assertEqual(self._count('refresh', 'success'), 0)

    # ---- service-token (ServiceTokenView) ----
    def test_service_token_success_increments_service_token_success(self):
        admin = User.objects.create_user(username='adm', email='adm@example.com',
                                         password='pw', is_superuser=True, is_staff=True)
        target = User.objects.create_user(username='svc', email='svc@example.com', password='pw')
        self.client.force_authenticate(user=admin)
        resp = self.client.post('/api/auth/service-token/', {'email': target.email}, format='json')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self._count('service_token', 'success'), 1)

    def test_service_token_mint_exception_increments_service_token_failure(self):
        admin = User.objects.create_user(username='adm2', email='adm2@example.com',
                                         password='pw', is_superuser=True, is_staff=True)
        target = User.objects.create_user(username='svc2', email='svc2@example.com', password='pw')
        self.client.force_authenticate(user=admin)
        self.client.raise_request_exception = False
        with mock.patch('identity.agent_tokens.PlatformRefreshToken.for_user',
                        side_effect=RuntimeError('mint backend down')):
            resp = self.client.post('/api/auth/service-token/', {'email': target.email}, format='json')
        self.assertGreaterEqual(resp.status_code, 500)
        self.assertEqual(self._count('service_token', 'failure'), 1)
        self.assertEqual(self._count('service_token', 'success'), 0)

    def test_password_change_does_not_pollute_service_token_stage(self):
        # PLAT-1278: PasswordChangeView now records `password`, not `service_token`.
        user = User.objects.create_user(username='pw1', email='pw1@example.com', password='oldpassword123')
        self.client.force_authenticate(user=user)
        resp = self.client.post('/api/auth/password/change/',
                                {'old_password': 'oldpassword123', 'new_password': 'brandnewpass456'},
                                format='json')
        # Whatever the exact route status, the service_token stage must stay clean.
        self.assertEqual(self._count('service_token', 'success'), 0)
