"""ID-36: segregation-of-duties, self-target bans, and break-glass audit controls."""

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from identity.admin_audit import (
    ACTION_ACCESS_REQUEST_REVIEW,
    ACTION_ADMIN_POLICY_DENIED,
    ACTION_ADMIN_SET_PASSWORD,
    ACTION_ADMIN_USER_DELETE,
    ACTION_ADMIN_USER_UPDATE,
    ACTION_USER_SERVICES_GRANT,
)
from identity.models import AdminAuditEvent, ServiceAccessRequest, Tool, UserProfile

User = get_user_model()


class SegregationOfDutiesTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.staff = User.objects.create_user(
            username='staff-id36', email='staff-id36@example.com', password='pw', is_staff=True,
        )
        self.superuser = User.objects.create_superuser(
            username='super-id36', email='super-id36@example.com', password='pw',
        )
        self.target = User.objects.create_user(
            username='target-id36', email='target-id36@example.com', password='old-password-1',
        )
        for user in (self.staff, self.superuser, self.target):
            UserProfile.objects.update_or_create(
                user=user,
                defaults={'approval_status': 'approved', 'lifecycle_state': 'active'},
            )
        self.priv_tool = Tool.objects.create(
            slug='id36-admin-tool', display_name='ID36 Admin Tool',
            is_active=True, is_default_enabled=False, requires_approval=True,
        )
        self.low_tool = Tool.objects.create(
            slug='id36-low-tool', display_name='ID36 Low Tool',
            is_active=True, is_default_enabled=False, requires_approval=False,
        )

    def _as(self, user):
        self.client.force_authenticate(user=user)
        return self.client

    def test_self_access_request_review_is_denied_and_audit_logged(self):
        req = ServiceAccessRequest.objects.create(
            user=self.staff, tool=self.priv_tool, reason='approve myself',
        )

        resp = self._as(self.staff).patch(
            f'/api/auth/admin/requests/{req.id}/',
            {'status': 'approved', 'review_note': 'self'},
            format='json',
        )

        self.assertEqual(resp.status_code, 403)
        req.refresh_from_db()
        self.assertEqual(req.status, 'pending')
        event = AdminAuditEvent.objects.get()
        self.assertEqual(event.action, ACTION_ADMIN_POLICY_DENIED)
        self.assertEqual(event.after['reason_code'], 'self_access_request_review_denied')
        self.assertEqual(event.after['attempted_action'], ACTION_ACCESS_REQUEST_REVIEW)
        self.assertEqual(event.target_id, str(req.id))

    def test_self_privileged_service_grant_is_denied_and_audit_logged(self):
        resp = self._as(self.staff).post(
            f'/api/auth/admin/users/{self.staff.id}/services/',
            {'service_slugs': [self.priv_tool.slug], 'action': 'grant'},
            format='json',
        )

        self.assertEqual(resp.status_code, 403)
        profile = UserProfile.objects.get(user=self.staff)
        self.assertNotIn(self.priv_tool.slug, profile.enabled_tools.values_list('slug', flat=True))
        event = AdminAuditEvent.objects.get()
        self.assertEqual(event.action, ACTION_ADMIN_POLICY_DENIED)
        self.assertEqual(event.after['reason_code'], 'self_privileged_service_change_denied')
        self.assertEqual(event.after['attempted']['service_slugs'], [self.priv_tool.slug])

    def test_low_risk_self_service_grant_still_allowed(self):
        resp = self._as(self.staff).post(
            f'/api/auth/admin/users/{self.staff.id}/services/',
            {'service_slugs': [self.low_tool.slug], 'action': 'grant'},
            format='json',
        )

        self.assertEqual(resp.status_code, 200)
        event = AdminAuditEvent.objects.get()
        self.assertEqual(event.action, ACTION_USER_SERVICES_GRANT)
        self.assertIn(self.low_tool.slug, event.after['enabled_services'])

    def test_self_privileged_service_revoke_is_denied_and_audit_logged(self):
        profile = UserProfile.objects.get(user=self.staff)
        profile.enabled_tools.add(self.priv_tool)

        resp = self._as(self.staff).post(
            f'/api/auth/admin/users/{self.staff.id}/services/',
            {'service_slugs': [self.priv_tool.slug], 'action': 'revoke'},
            format='json',
        )

        self.assertEqual(resp.status_code, 403)
        self.assertIn(self.priv_tool, UserProfile.objects.get(user=self.staff).enabled_tools.all())
        event = AdminAuditEvent.objects.get()
        self.assertEqual(event.action, ACTION_ADMIN_POLICY_DENIED)
        self.assertEqual(event.after['reason_code'], 'self_privileged_service_change_denied')
        self.assertEqual(event.after['attempted']['action'], 'revoke')

    def test_non_superuser_break_glass_attempt_is_denied_and_audit_logged(self):
        resp = self._as(self.staff).post(
            f'/api/auth/admin/users/{self.staff.id}/services/',
            {
                'service_slugs': [self.priv_tool.slug],
                'action': 'grant',
                'break_glass': True,
                'break_glass_reason': 'not eligible',
            },
            format='json',
        )

        self.assertEqual(resp.status_code, 403)
        event = AdminAuditEvent.objects.get()
        self.assertEqual(event.action, ACTION_ADMIN_POLICY_DENIED)
        self.assertEqual(event.after['reason_code'], 'self_privileged_service_change_denied')

    def test_self_password_reset_denied_without_break_glass_no_secret_audit(self):
        resp = self._as(self.superuser).post(
            f'/api/auth/admin/users/{self.superuser.id}/set-password/',
            {'password': 'New-Secure-Pass-123!'},
            format='json',
        )

        self.assertEqual(resp.status_code, 403)
        event = AdminAuditEvent.objects.get()
        self.assertEqual(event.action, ACTION_ADMIN_POLICY_DENIED)
        self.assertEqual(event.after['reason_code'], 'self_admin_password_set_denied')
        self.assertNotIn('New-Secure-Pass-123!', event.hash_payload())

    def test_self_password_reset_break_glass_requires_reason_and_is_elevated(self):
        no_reason = self._as(self.superuser).post(
            f'/api/auth/admin/users/{self.superuser.id}/set-password/',
            {'password': 'New-Secure-Pass-123!', 'break_glass': True},
            format='json',
        )
        self.assertEqual(no_reason.status_code, 403)

        resp = self._as(self.superuser).post(
            f'/api/auth/admin/users/{self.superuser.id}/set-password/',
            {
                'password': 'New-Secure-Pass-123!',
                'break_glass': True,
                'break_glass_reason': 'recover only remaining superuser account',
            },
            format='json',
        )

        self.assertEqual(resp.status_code, 200)
        event = AdminAuditEvent.objects.order_by('seq').last()
        self.assertEqual(event.action, ACTION_ADMIN_SET_PASSWORD)
        self.assertTrue(event.after['break_glass'])
        self.assertEqual(event.after['break_glass_reason'], 'recover only remaining superuser account')
        self.assertNotIn('New-Secure-Pass-123!', event.hash_payload())

    def test_string_false_does_not_enable_public_break_glass(self):
        resp = self._as(self.superuser).post(
            f'/api/auth/admin/users/{self.superuser.id}/set-password/',
            {
                'password': 'New-Secure-Pass-123!',
                'break_glass': 'false',
                'break_glass_reason': 'routine admin note',
            },
            format='json',
        )

        self.assertEqual(resp.status_code, 403)
        event = AdminAuditEvent.objects.get()
        self.assertEqual(event.action, ACTION_ADMIN_POLICY_DENIED)
        self.assertEqual(event.after['reason_code'], 'self_admin_password_set_denied')

    def test_self_admin_update_denied_unless_break_glass(self):
        path = f'/api/internal/admin/users/{self.superuser.id}/'
        denied = self._as(self.superuser).patch(path, {'is_staff': False}, format='json')
        self.assertEqual(denied.status_code, 403)
        self.superuser.refresh_from_db()
        self.assertTrue(self.superuser.is_staff)
        denied_event = AdminAuditEvent.objects.get()
        self.assertEqual(denied_event.action, ACTION_ADMIN_POLICY_DENIED)
        self.assertEqual(denied_event.after['reason_code'], 'self_admin_user_update_denied')

        allowed = self._as(self.superuser).patch(
            path,
            {
                'first_name': 'Breakglass',
                'break_glass': True,
                'break_glass_reason': 'repair own profile metadata during incident',
            },
            format='json',
        )
        self.assertEqual(allowed.status_code, 200)
        event = AdminAuditEvent.objects.order_by('seq').last()
        self.assertEqual(event.action, ACTION_ADMIN_USER_UPDATE)
        self.assertTrue(event.after['break_glass'])
        self.assertEqual(event.after['break_glass_reason'], 'repair own profile metadata during incident')

    def test_string_false_does_not_enable_internal_break_glass(self):
        path = f'/api/internal/admin/users/{self.superuser.id}/'
        resp = self._as(self.superuser).patch(
            path,
            {
                'first_name': 'NotBreakglass',
                'break_glass': 'false',
                'break_glass_reason': 'routine admin note',
            },
            format='json',
        )

        self.assertEqual(resp.status_code, 403)
        self.superuser.refresh_from_db()
        self.assertNotEqual(self.superuser.first_name, 'NotBreakglass')
        event = AdminAuditEvent.objects.get()
        self.assertEqual(event.action, ACTION_ADMIN_POLICY_DENIED)
        self.assertEqual(event.after['reason_code'], 'self_admin_user_update_denied')

    def test_self_delete_denied_unless_break_glass(self):
        denied = self._as(self.superuser).delete(f'/api/internal/admin/users/{self.superuser.id}/delete/')
        self.assertEqual(denied.status_code, 403)
        self.superuser.refresh_from_db()
        self.assertTrue(self.superuser.is_active)
        denied_event = AdminAuditEvent.objects.get()
        self.assertEqual(denied_event.action, ACTION_ADMIN_POLICY_DENIED)
        self.assertEqual(denied_event.after['reason_code'], 'self_admin_user_delete_denied')

        resp = self._as(self.superuser).delete(
            f'/api/internal/admin/users/{self.superuser.id}/delete/',
            {'break_glass': True, 'break_glass_reason': 'compromised admin session containment'},
            format='json',
        )
        self.assertEqual(resp.status_code, 200)
        event = AdminAuditEvent.objects.order_by('seq').last()
        self.assertEqual(event.action, ACTION_ADMIN_USER_DELETE)
        self.assertTrue(event.after['break_glass'])
        self.assertEqual(event.after['break_glass_reason'], 'compromised admin session containment')
