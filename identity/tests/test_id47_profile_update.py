import os
from unittest import mock

os.environ.setdefault('SHIZUHA_OAUTH_KEY_DIR', '/tmp/shizuha-id47-oauth-keys')

from django.contrib.auth import get_user_model
from django.db import IntegrityError
from rest_framework import status
from rest_framework.test import APITestCase

from identity.models import UserProfile

USER_URL = '/api/auth/user/'
PROFILE_URL = '/api/auth/profile/'
PASSWORD = 'Str0ng!Pass-ID47'


class ProfileUpdateValidationTests(APITestCase):
    def setUp(self):
        self.User = get_user_model()
        self.user = self.User.objects.create_user(
            username='owner',
            email='owner@example.com',
            password=PASSWORD,
            first_name='Owner',
            last_name='Original',
        )
        self.profile = self.user.profile
        self.profile.approval_status = 'approved'
        self.profile.lifecycle_state = 'active'
        self.profile.save(update_fields=['approval_status', 'lifecycle_state'])
        self.client.force_authenticate(self.user)

    def test_user_update_allows_mutable_fields_canonicalizes_and_audits(self):
        with self.assertLogs('identity.audit', level='INFO') as logs:
            response = self.client.patch(
                USER_URL,
                data={
                    'username': '  OWNER_NEW  ',
                    'email': ' OWNER.NEW@Example.COM ',
                    'first_name': '  Alice  ',
                    'last_name': '  Example  ',
                },
                content_type='application/json',
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content)
        self.user.refresh_from_db()
        self.assertEqual(self.user.username, 'owner_new')
        self.assertEqual(self.user.email, 'owner.new@example.com')
        self.assertEqual(self.user.first_name, 'Alice')
        self.assertEqual(self.user.last_name, 'Example')
        self.assertIn('profile update surface=auth.user', '\n'.join(logs.output))

        lookup = self.client.get(USER_URL)
        self.assertEqual(lookup.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json(), lookup.json())

    def test_user_update_rejects_invalid_empty_and_immutable_fields(self):
        cases = [
            ({'username': 'bad-name!'}, 'Username can only contain'),
            ({'username': '   '}, 'Username cannot be empty'),
            ({'email': 'not-an-email'}, 'Enter a valid email'),
            ({'email': '   '}, 'Email cannot be empty'),
            ({'id': 999}, "Field 'id' is immutable"),
            ({'is_staff': True}, "Field 'is_staff' is immutable"),
            ({'unknown_field': 'x'}, "Field 'unknown_field' is not a supported"),
        ]
        for payload, expected in cases:
            with self.subTest(payload=payload):
                response = self.client.patch(USER_URL, data=payload, content_type='application/json')
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, response.content)
                self.assertIn(expected, response.json()['error'])

    def test_user_update_rejects_duplicate_username_and_email(self):
        self.User.objects.create_user(username='taken', email='taken@example.com', password=PASSWORD)

        response = self.client.patch(USER_URL, data={'username': ' TAKEN '}, content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('already taken', response.json()['error'])

        response = self.client.patch(USER_URL, data={'email': ' TAKEN@EXAMPLE.COM '}, content_type='application/json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('already taken', response.json()['error'])

    def test_user_update_integrity_race_returns_conflict_without_partial_update(self):
        with mock.patch.object(self.User, 'save', autospec=True, side_effect=IntegrityError('canonical race')):
            response = self.client.patch(
                USER_URL,
                data={'username': 'race_winner'},
                content_type='application/json',
            )

        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT, response.content)
        self.assertIn('conflicted', response.json()['error'])
        self.user.refresh_from_db()
        self.assertEqual(self.user.username, 'owner')

    def test_profile_update_allows_mutable_fields_updates_timestamp_and_audits(self):
        before_updated_at = UserProfile.objects.get(pk=self.profile.pk).updated_at
        with self.assertLogs('identity.audit', level='INFO') as logs:
            response = self.client.patch(
                PROFILE_URL,
                data={
                    'profile_picture': 'https://example.com/avatar.png',
                    'timezone': 'Asia/Kolkata',
                    'display_currency': 'inr',
                    'country': 'India',
                    'city': 'Bengaluru',
                    'latitude': 12.9716,
                    'longitude': 77.5946,
                    'tool_preferences': {'theme': 'dark'},
                },
                content_type='application/json',
            )

        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content)
        self.profile.refresh_from_db()
        self.assertEqual(self.profile.profile_picture, 'https://example.com/avatar.png')
        self.assertEqual(self.profile.timezone, 'Asia/Kolkata')
        self.assertEqual(self.profile.display_currency, 'INR')
        self.assertEqual(self.profile.country, 'India')
        self.assertEqual(self.profile.city, 'Bengaluru')
        self.assertEqual(self.profile.latitude, 12.9716)
        self.assertEqual(self.profile.longitude, 77.5946)
        self.assertEqual(self.profile.tool_preferences, {'theme': 'dark'})
        self.assertGreater(self.profile.updated_at, before_updated_at)
        self.assertIn('profile update surface=identity.profile', '\n'.join(logs.output))

        lookup = self.client.get(PROFILE_URL)
        self.assertEqual(lookup.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json(), lookup.json())

    def test_profile_update_rejects_immutable_and_invalid_fields(self):
        cases = [
            ({'google_id': 'google-oauth-id'}, "Field 'google_id' is immutable"),
            ({'account_type': 'agent'}, "Field 'account_type' is immutable"),
            ({'enabled_tools': []}, "Field 'enabled_tools' is immutable"),
            ({'latitude': 120}, 'Ensure this value is less than or equal to 90'),
            ({'longitude': -200}, 'Ensure this value is greater than or equal to -180'),
            ({'tool_preferences': ['not', 'an', 'object']}, 'Expected a dictionary'),
            ({'unknown_field': 'x'}, "Field 'unknown_field' is not a supported"),
        ]
        for payload, expected in cases:
            with self.subTest(payload=payload):
                response = self.client.patch(PROFILE_URL, data=payload, content_type='application/json')
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, response.content)
                self.assertIn(expected, response.json()['error'])
