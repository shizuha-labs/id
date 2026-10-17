"""The resource-server authority must agree with real ID session logout."""
import secrets
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone
from rest_framework.test import APITestCase

from identity.models import ActiveSession, UserProfile


class SessionRevocationStatusTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.password = secrets.token_urlsafe(24)
        self.user = get_user_model().objects.create_user(
            username='session-status', email='session-status@example.com',
            password=self.password,
        )
        patcher = mock.patch('identity.views._fetch_membership_projection',
                             return_value=({}, [], {}))
        patcher.start()
        self.addCleanup(patcher.stop)

    def login(self):
        self.client.credentials()
        response = self.client.post('/api/auth/login/', {
            'username': self.user.username, 'password': self.password,
        }, format='json')
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()['tokens']

    def status(self, access):
        self.client.credentials()
        response = self.client.post('/api/oauth/revocation-status',
                                    {'token': access}, format='json')
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()

    def test_logout_denies_exact_session_and_preserves_other_and_fresh_sessions(self):
        first, second = self.login(), self.login()
        before = self.status(first['access'])
        self.assertTrue(before['active'])
        self.assertTrue(self.status(second['access'])['active'])
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + first['access'])
        response = self.client.post('/api/auth/logout/',
            {'refresh_token': first['refresh']}, format='json')
        self.assertEqual(response.status_code, 200, response.content)
        after = self.status(first['access'])
        self.assertFalse(after['active'])
        self.assertEqual(after['token_version'], before['token_version'])
        self.assertTrue(self.status(second['access'])['active'])
        self.assertTrue(self.status(self.login()['access'])['active'])
        self.assertFalse(self.status(first['access'])['active'])

    def test_unknown_session_and_inactive_user_are_denied(self):
        first = self.login()
        self.assertTrue(self.status(first['access'])['active'])
        ActiveSession.objects.filter(user=self.user).delete()
        self.assertFalse(self.status(first['access'])['active'])
        second = self.login()
        self.user.is_active = False
        self.user.save(update_fields=['is_active'])
        self.assertFalse(self.status(second['access'])['active'])

    def test_user_cutoff_is_authoritative_for_resource_servers(self):
        first = self.login()
        self.assertTrue(self.status(first['access'])['active'])
        UserProfile.objects.filter(user=self.user).update(access_revoked_before=timezone.now())
        cache.clear()
        self.assertFalse(self.status(first['access'])['active'])
