"""ID-24 P1 (HLD ID-3 §4.2, L-1): the admin approve/deny endpoint is staff-only.

Previously ``UserApprovalView`` was ``IsAuthenticated`` only, so ANY authenticated
user could approve a pending account (escalation past admin review → is_active=True
+ default tools) or deny/deactivate another pending user (griefing). Agents are
provisioned via the internal service API (which sets approval_status='approved'
explicitly), so gating this endpoint to staff does not affect Hive provisioning.
"""
from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIRequestFactory, force_authenticate

from identity.models import UserProfile
from identity.views import UserApprovalView

User = get_user_model()


class ApprovalAuthzTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        # A pending account awaiting admin review.
        self.pending = User.objects.create_user(
            username='pending', password='pw', email='p@shizuha.com', is_active=False,
        )
        UserProfile.objects.update_or_create(
            user=self.pending, defaults={'approval_status': 'pending'},
        )

    def _review(self, actor, status_value):
        req = self.factory.patch(
            f'/admin/users/{self.pending.id}/approve/',
            {'status': status_value}, format='json',
        )
        force_authenticate(req, user=actor)
        return UserApprovalView.as_view()(req, user_id=self.pending.id)

    def _profile_status(self):
        return UserProfile.objects.get(user=self.pending).approval_status

    def test_non_staff_cannot_approve(self):
        attacker = User.objects.create_user(username='attacker', password='pw', email='a@shizuha.com')
        resp = self._review(attacker, 'approved')
        self.assertEqual(resp.status_code, 403)
        self.pending.refresh_from_db()
        self.assertFalse(self.pending.is_active)          # not escalated
        self.assertEqual(self._profile_status(), 'pending')

    def test_non_staff_cannot_deny(self):
        griefer = User.objects.create_user(username='griefer', password='pw', email='g@shizuha.com')
        resp = self._review(griefer, 'denied')
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(self._profile_status(), 'pending')  # not griefed

    def test_staff_can_approve(self):
        admin = User.objects.create_user(
            username='admin', password='pw', email='admin@shizuha.com', is_staff=True,
        )
        resp = self._review(admin, 'approved')
        self.assertIn(resp.status_code, (200, 201))
        self.pending.refresh_from_db()
        self.assertTrue(self.pending.is_active)
        self.assertEqual(self._profile_status(), 'approved')
