"""ID-33: server-side permission gates for privileged ID admin endpoints."""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from identity.models import ServiceAccessRequest, Tool, UserProfile

User = get_user_model()


class AdminPermissionGateTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.regular = User.objects.create_user(
            username='regular-id33',
            email='regular-id33@example.com',
            password='pw',
        )
        self.staff = User.objects.create_user(
            username='staff-id33',
            email='staff-id33@example.com',
            password='pw',
            is_staff=True,
        )
        self.superuser = User.objects.create_superuser(
            username='super-id33',
            email='super-id33@example.com',
            password='pw',
        )
        self.target = User.objects.create_user(
            username='target-id33',
            email='target-id33@example.com',
            password='pw',
            is_active=False,
        )
        UserProfile.objects.update_or_create(
            user=self.target,
            defaults={'approval_status': 'pending'},
        )
        self.tool = Tool.objects.create(
            slug='id33-notes',
            display_name='ID33 Notes',
            is_active=True,
            is_default_enabled=False,
            requires_approval=True,
        )
        self.access_request = ServiceAccessRequest.objects.create(
            user=self.target,
            tool=self.tool,
            reason='Need notes',
        )

    def _as(self, user):
        self.client.force_authenticate(user=user)
        return self.client

    def assert_regular_forbidden(self, method, path, data=None):
        response = getattr(self._as(self.regular), method)(path, data or {}, format='json')
        self.assertEqual(response.status_code, 403, path)

    def test_public_staff_admin_endpoints_reject_non_admins_and_allow_staff(self):
        staff_cases = [
            ('get', '/api/auth/admin/services/', None),
            ('patch', f'/api/auth/admin/services/{self.tool.slug}/', {'requires_approval': False}),
            ('get', f'/api/auth/admin/users/{self.target.id}/services/', None),
            ('post', f'/api/auth/admin/users/{self.target.id}/services/', {
                'service_slugs': [self.tool.slug],
                'action': 'grant',
            }),
            ('get', '/api/auth/admin/requests/', None),
            ('patch', f'/api/auth/admin/requests/{self.access_request.id}/', {
                'status': 'approved',
                'review_note': 'ok',
            }),
            ('get', '/api/auth/admin/users/pending/', None),
            ('get', '/api/auth/admin/users/pending/count/', None),
            ('patch', f'/api/auth/admin/users/{self.target.id}/approve/', {'status': 'approved'}),
        ]

        for method, path, data in staff_cases:
            with self.subTest(path=path, role='regular'):
                self.assert_regular_forbidden(method, path, data)

        for method, path, data in staff_cases:
            with self.subTest(path=path, role='staff'):
                response = getattr(self._as(self.staff), method)(path, data or {}, format='json')
                self.assertLess(response.status_code, 400, (path, response.status_code, response.data))

    def test_admin_set_password_requires_superuser(self):
        path = f'/api/auth/admin/users/{self.target.id}/set-password/'
        payload = {'password': 'New-Secure-Pass-123!'}

        self.assert_regular_forbidden('post', path, payload)
        response = self._as(self.staff).post(path, payload, format='json')
        self.assertEqual(response.status_code, 403)

        response = self._as(self.superuser).post(path, payload, format='json')
        self.assertEqual(response.status_code, 200)

    def test_internal_admin_user_endpoints_require_superuser(self):
        create_payload = {
            'username': 'created-id33',
            'email': 'created-id33@example.com',
            'password': 'Created-Secure-Pass-123!',
        }
        superuser_cases = [
            ('get', '/api/internal/admin/users/', None),
            ('post', '/api/internal/admin/users/create/', create_payload),
            ('patch', f'/api/internal/admin/users/{self.target.id}/', {'first_name': 'Renamed'}),
            ('delete', f'/api/internal/admin/users/{self.target.id}/delete/', None),
        ]

        for method, path, data in superuser_cases:
            with self.subTest(path=path, role='regular'):
                self.assert_regular_forbidden(method, path, data)

        for method, path, data in superuser_cases:
            with self.subTest(path=path, role='staff'):
                response = getattr(self._as(self.staff), method)(path, data or {}, format='json')
                self.assertEqual(response.status_code, 403, path)

        # Use fresh targets where a successful mutation would affect later cases.
        response = self._as(self.superuser).get('/api/internal/admin/users/')
        self.assertEqual(response.status_code, 200)

        response = self._as(self.superuser).post('/api/internal/admin/users/create/', create_payload, format='json')
        self.assertEqual(response.status_code, 201)

        response = self._as(self.superuser).patch(
            f'/api/internal/admin/users/{self.target.id}/',
            {'first_name': 'Renamed'},
            format='json',
        )
        self.assertEqual(response.status_code, 200)

        delete_target = User.objects.create_user(
            username='delete-id33',
            email='delete-id33@example.com',
            password='pw',
        )
        path = f'/api/internal/admin/users/{delete_target.id}/delete/'
        # Pending accounts cannot skip the audited lifecycle transition.
        self.assertEqual(self._as(self.superuser).delete(path).status_code, 409)
        from identity.lifecycle import LifecycleState, transition_user
        transition_user(delete_target, LifecycleState.ACTIVE,
                        actor=self.superuser, reason='permission test approval')
        response = self._as(self.superuser).delete(path)
        self.assertEqual(response.status_code, 200)
        delete_target.refresh_from_db()
        self.assertFalse(delete_target.is_active)
        self.assertEqual(delete_target.profile.lifecycle_state, LifecycleState.DELETED)
