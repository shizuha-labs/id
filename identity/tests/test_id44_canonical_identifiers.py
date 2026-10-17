import os
from unittest import mock

os.environ.setdefault('SHIZUHA_OAUTH_KEY_DIR', '/tmp/shizuha-id44-oauth-keys')

from django.contrib.auth import get_user_model
from django.db import IntegrityError, connection, transaction
from django.test import override_settings
from rest_framework import status
from rest_framework.test import APITestCase

REGISTER_URL = '/api/auth/register/'
LOGIN_URL = '/api/auth/login/'
USER_URL = '/api/auth/user/'
PASSWORD = 'Str0ng!Pass-ID44'
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


class CanonicalIdentifierTests(APITestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if connection.vendor == 'sqlite':
            with connection.cursor() as cursor:
                cursor.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS identity_user_username_canonical_uniq "
                    "ON auth_user (LOWER(TRIM(username))) "
                    "WHERE username IS NOT NULL AND TRIM(username) <> ''"
                )
                cursor.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS identity_user_email_canonical_uniq "
                    "ON auth_user (LOWER(TRIM(email))) "
                    "WHERE email IS NOT NULL AND TRIM(email) <> ''"
                )

    def payload(self, username, email):
        return {
            'username': username,
            'email': email,
            'password': PASSWORD,
            'password2': PASSWORD,
        }

    @override_settings(ALLOW_DRIVE_SELFREGISTRATION=False)
    def test_registration_trims_and_casefolds_identifiers(self):
        response = self.client.post(
            REGISTER_URL,
            data=self.payload('  Mixed_Case  ', '  Mixed.Email@Example.COM  '),
            content_type='application/json',
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        user = get_user_model().objects.get()
        self.assertEqual(user.username, 'mixed_case')
        self.assertEqual(user.email, 'mixed.email@example.com')

    @override_settings(ALLOW_DRIVE_SELFREGISTRATION=False)
    def test_registration_rejects_case_and_whitespace_duplicate(self):
        User = get_user_model()
        User.objects.create_user(username='alice', email='alice@example.com', password=PASSWORD)

        response = self.client.post(
            REGISTER_URL,
            data=self.payload('  ALICE  ', 'other@example.com'),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Username already exists', response.json()['error'])

        response = self.client.post(
            REGISTER_URL,
            data=self.payload('other', '  ALICE@EXAMPLE.COM  '),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Email already exists', response.json()['error'])

    def test_login_accepts_original_or_canonical_forms(self):
        user = get_user_model().objects.create_user(
            username='login_case',
            email='login.case@example.com',
            password=PASSWORD,
            is_active=True,
        )
        user.profile.approval_status = 'approved'
        user.profile.lifecycle_state = 'active'
        user.profile.save(update_fields=['approval_status', 'lifecycle_state'])

        for identifier in (' LOGIN_CASE ', ' Login.Case@Example.COM '):
            response = self.client.post(
                LOGIN_URL,
                data={'username': identifier, 'password': PASSWORD},
                content_type='application/json',
            )
            self.assertEqual(response.status_code, status.HTTP_200_OK, response.content)

    def test_profile_update_canonicalizes_and_rejects_duplicates(self):
        User = get_user_model()
        user = User.objects.create_user(username='owner', email='owner@example.com', password=PASSWORD)
        User.objects.create_user(username='taken', email='taken@example.com', password=PASSWORD)
        self.client.force_authenticate(user)

        response = self.client.patch(
            USER_URL,
            data={'username': '  OWNER_NEW  ', 'email': ' OWNER.NEW@Example.COM '},
            content_type='application/json',
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.content)
        user.refresh_from_db()
        self.assertEqual(user.username, 'owner_new')
        self.assertEqual(user.email, 'owner.new@example.com')

        response = self.client.patch(
            USER_URL,
            data={'username': 'TAKEN'},
            content_type='application/json',
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        response = self.client.patch(
            USER_URL,
            data={'email': ' TAKEN@EXAMPLE.COM '},
            content_type='application/json',
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_database_unique_index_blocks_canonical_races(self):
        if connection.vendor not in {'sqlite', 'postgresql'}:
            self.skipTest('functional unique index assertion is sqlite/postgresql-specific')
        User = get_user_model()
        User.objects.create_user(username='race', email='race@example.com', password=PASSWORD)

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                User.objects.create_user(username=' RACE ', email='race2@example.com', password=PASSWORD)
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                User.objects.create_user(username='race2', email=' RACE@EXAMPLE.COM ', password=PASSWORD)
