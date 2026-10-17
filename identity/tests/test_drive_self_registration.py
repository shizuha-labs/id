from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework import status
from identity.agent_tokens import PlatformAccessToken

from identity.models import Tool


REGISTER_URL = '/api/auth/register/'
PASSWORD = 'Str0ng!Pass-DRV-21-tests'
_projection_patcher = None


def setUpModule():
    global _projection_patcher
    _projection_patcher = patch(
        'identity.views._fetch_membership_projection',
        return_value=({}, [], {}),
    )
    _projection_patcher.start()


def tearDownModule():
    _projection_patcher.stop()


class DriveSelfRegistrationTests(TestCase):
    def setUp(self):
        self._seed_tools()

    def _seed_tools(self):
        for slug in ('id', 'drive', 'hive', 'pulse', 'connect', 'wiki', 'admin', 'fleet'):
            Tool.objects.update_or_create(
                slug=slug,
                defaults={
                    'display_name': slug.title(),
                    'is_active': True,
                    'is_default_enabled': slug in {'id', 'hive'},
                    'requires_approval': False,
                    'requires_superuser': slug in {'admin', 'fleet'},
                },
            )

    def _payload(self, username, email, *, intent='drive'):
        data = {
            'username': username,
            'email': email,
            'password': PASSWORD,
            'password2': PASSWORD,
            'first_name': 'Drive',
            'last_name': 'Tester',
        }
        if intent is not None:
            data['intent'] = intent
        return data

    @override_settings(ALLOW_DRIVE_SELFREGISTRATION=False)
    def test_drive_intent_preserves_pending_manual_path_when_flag_disabled(self):
        response = self.client.post(
            REGISTER_URL,
            data=self._payload('drvflagoff', 'drvflagoff@example.com'),
            content_type='application/json',
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        body = response.json()
        self.assertTrue(body['pending_approval'])
        self.assertNotIn('access', body)
        self.assertNotIn('refresh', body)
        self.assertNotIn('drive_signup', body)

        user = get_user_model().objects.get(username='drvflagoff')
        self.assertFalse(user.is_active)
        self.assertEqual(user.profile.approval_status, 'pending')
        self.assertEqual(
            set(user.profile.enabled_tools.values_list('slug', flat=True)),
            {'id', 'hive', 'mail'},
        )

    @override_settings(ALLOW_DRIVE_SELFREGISTRATION=True)
    @patch('identity.views._fetch_project_memberships', return_value=([], {}))
    @patch('identity.views._fetch_org_memberships', return_value={})
    def test_drive_intent_auto_approves_free_user_and_mints_drive_only_token(
        self, _orgs, _projects
    ):
        response = self.client.post(
            REGISTER_URL,
            data=self._payload('drvactive', 'drvactive@example.com'),
            content_type='application/json',
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        body = response.json()
        self.assertTrue(body['drive_signup'])
        self.assertIn('tokens', body)
        self.assertIn('access', body['tokens'])
        self.assertIn('refresh', body['tokens'])
        # Backward-compatible rollout shape for older clients.
        self.assertIn('access', body)
        self.assertIn('refresh', body)
        self.assertNotIn('pending_approval', body)

        user = get_user_model().objects.get(username='drvactive')
        self.assertTrue(user.is_active)
        self.assertEqual(user.profile.approval_status, 'approved')
        self.assertEqual(user.profile.subscription_tier, 'free')
        self.assertEqual(
            set(user.profile.enabled_tools.values_list('slug', flat=True)),
            {'id', 'drive'},
        )

        access = PlatformAccessToken(body['tokens']['access'])
        self.assertEqual(set(access['enabled_services']), {'id', 'drive'})
        self.assertFalse({'hive', 'pulse', 'connect', 'wiki', 'admin', 'fleet'} & set(access['enabled_services']))

    @override_settings(ALLOW_DRIVE_SELFREGISTRATION=True)
    def test_non_drive_registration_remains_pending_even_when_flag_enabled(self):
        response = self.client.post(
            REGISTER_URL,
            data=self._payload('ordinary', 'ordinary@example.com', intent='hive'),
            content_type='application/json',
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        body = response.json()
        self.assertTrue(body['pending_approval'])
        self.assertNotIn('access', body)
        self.assertNotIn('refresh', body)
        self.assertNotIn('drive_signup', body)

        user = get_user_model().objects.get(username='ordinary')
        self.assertFalse(user.is_active)
        self.assertEqual(user.profile.approval_status, 'pending')
        self.assertEqual(
            set(user.profile.enabled_tools.values_list('slug', flat=True)),
            {'id', 'hive', 'mail'},
        )
