from unittest import mock

import jwt
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from identity.models import UserProfile

_projection_patcher = None


def setUpModule():
    global _projection_patcher
    _projection_patcher = mock.patch(
        'identity.views._fetch_membership_projection',
        return_value=({}, [], {}),
    )
    _projection_patcher.start()


def tearDownModule():
    _projection_patcher.stop()


@override_settings(
    TWOFA_LOGIN_ENFORCEMENT='off',
    REST_AUTH={
        'JWT_AUTH_COOKIE': 'shizuha-access-token',
        'JWT_AUTH_REFRESH_COOKIE': 'shizuha-refresh-token',
        'JWT_AUTH_HTTPONLY': True,
        'JWT_AUTH_SECURE': True,
        'JWT_AUTH_SAMESITE': 'Lax',
    },
)
class BrowserAuthCookieTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        user_model = get_user_model()
        self.user = user_model.objects.create_user(
            username='hiveowner',
            email='hiveowner@example.com',
            password='correct-password',
        )
        UserProfile.objects.get_or_create(user=self.user)

    def test_password_login_sets_browser_jwt_cookies_for_hive_routes(self):
        response = self.client.post(
            '/api/auth/login/',
            {'username': 'hiveowner', 'password': 'correct-password'},
            format='json',
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn('tokens', response.data)
        self.assertIn('shizuha-access-token', response.cookies)
        self.assertIn('shizuha-refresh-token', response.cookies)
        self.assertEqual(response.cookies['shizuha-access-token'].value, response.data['tokens']['access'])
        self.assertEqual(response.cookies['shizuha-access-token']['path'], '/')
        self.assertTrue(response.cookies['shizuha-access-token']['httponly'])
        self.assertTrue(response.cookies['shizuha-access-token']['secure'])
        self.assertEqual(response.cookies['shizuha-access-token']['samesite'], 'Lax')
        claims = jwt.decode(
            response.data['tokens']['access'],
            options={'verify_signature': False},
        )
        self.assertEqual(claims['aud'], '*')
        self.assertEqual(claims['iss'], 'https://shizuha.com/id')
