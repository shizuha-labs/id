"""ID-32: lifecycle FSM + soft-delete + reactivation (HLD ID-3 §4.1/§4.3/§4.6).

Covers every legal and illegal transition, legacy-field sync, per-transition
audit rows (applied AND rejected), the soft-delete admin path (audit survives),
reactivation from the defined states, and the pending list/count regression.
"""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from identity.lifecycle import (
    LEGAL_TRANSITIONS,
    IllegalLifecycleTransition,
    LifecycleState,
    derive_lifecycle_state,
    transition_user,
)
from identity.models import UserLifecycleAudit, UserProfile

User = get_user_model()

ALL_STATES = sorted(LifecycleState.ALL)


def _user(username, *, state=None, is_active=False):
    user = User.objects.create_user(
        username=username, email=f'{username}@example.com', password='Pass123!x',
        is_active=is_active,
    )
    if state:
        profile = user.profile
        profile.lifecycle_state = state
        profile.save(update_fields=['lifecycle_state'])
    return user


class FsmTransitionTests(TestCase):
    def test_every_legal_transition_applies_and_audits(self):
        for i, (from_state, to_state) in enumerate(sorted(LEGAL_TRANSITIONS)):
            user = _user(f'legal{i}', state=from_state)
            profile = transition_user(user, to_state, reason='test')
            self.assertEqual(profile.lifecycle_state, to_state)
            audit = UserLifecycleAudit.objects.filter(user=user).latest('created_at')
            self.assertEqual((audit.from_state, audit.to_state, audit.outcome),
                             (from_state, to_state, 'applied'))

    def test_every_illegal_transition_rejected_and_audited(self):
        illegal = [
            (f, t) for f in ALL_STATES for t in ALL_STATES
            if f != t and (f, t) not in LEGAL_TRANSITIONS
        ]
        self.assertTrue(illegal, 'expected at least one illegal pair')
        for i, (from_state, to_state) in enumerate(illegal):
            user = _user(f'illegal{i}', state=from_state)
            with self.assertRaises(IllegalLifecycleTransition):
                transition_user(user, to_state)
            profile = UserProfile.objects.get(user=user)
            self.assertEqual(profile.lifecycle_state, from_state,
                             'illegal transition must not mutate state')
            audit = UserLifecycleAudit.objects.filter(user=user).latest('created_at')
            self.assertEqual(audit.outcome, 'rejected')

    def test_deleted_is_terminal(self):
        user = _user('terminal', state=LifecycleState.DELETED)
        for target in (LifecycleState.ACTIVE, LifecycleState.DEACTIVATED,
                       LifecycleState.PENDING, LifecycleState.DENIED):
            with self.assertRaises(IllegalLifecycleTransition):
                transition_user(user, target)

    def test_legacy_fields_stay_in_sync(self):
        user = _user('sync', state=LifecycleState.PENDING)
        transition_user(user, LifecycleState.ACTIVE)
        user.refresh_from_db(); profile = user.profile; profile.refresh_from_db()
        self.assertTrue(user.is_active)
        self.assertEqual(profile.approval_status, 'approved')

        transition_user(user, LifecycleState.DEACTIVATED)
        user.refresh_from_db(); profile.refresh_from_db()
        self.assertFalse(user.is_active)
        self.assertEqual(profile.approval_status, 'approved')
        self.assertIsNotNone(profile.deactivated_at)

        transition_user(user, LifecycleState.ACTIVE, reason='reactivate')
        user.refresh_from_db(); profile.refresh_from_db()
        self.assertTrue(user.is_active)
        self.assertIsNone(profile.deactivated_at)

        transition_user(user, LifecycleState.DELETED)
        user.refresh_from_db(); profile.refresh_from_db()
        self.assertFalse(user.is_active)
        self.assertIsNotNone(profile.deleted_at)

    def test_transition_preserves_policy_saved_through_separate_profile(self):
        """Mirror the Mail lifecycle hook order across two top-level attempts."""
        for suffix in ('first', 'second'):
            user = User.objects.create(
                username=f'mail-canary-{suffix}',
                email=f'mail-canary-{suffix}@agents.shizuha.io',
                is_active=False,
                is_staff=False,
                is_superuser=False,
            )
            user.set_unusable_password()
            user.save(update_fields=['password'])

            profile = UserProfile.objects.select_for_update().get(user=user)
            profile.account_type = 'agent'
            profile.ownership_class = 'system_canary'
            profile.save(update_fields=[
                'account_type', 'ownership_class', 'updated_at',
            ])

            profile = transition_user(user, LifecycleState.ACTIVE, reason='mail canary')
            profile.refresh_from_db()
            self.assertEqual(profile.account_type, 'agent')
            self.assertEqual(profile.ownership_class, 'system_canary')

    def test_audit_records_actor(self):
        actor = _user('actor-admin', state=LifecycleState.ACTIVE, is_active=True)
        user = _user('subject', state=LifecycleState.PENDING)
        transition_user(user, LifecycleState.ACTIVE, actor=actor, reason='approved by admin')
        audit = UserLifecycleAudit.objects.filter(user=user).latest('created_at')
        self.assertEqual(audit.actor_id, actor.id)
        self.assertEqual(audit.reason, 'approved by admin')

    def test_derive_lifecycle_state_backfill_mapping(self):
        self.assertEqual(derive_lifecycle_state('denied', False), LifecycleState.DENIED)
        self.assertEqual(derive_lifecycle_state('pending', False), LifecycleState.PENDING)
        self.assertEqual(derive_lifecycle_state('approved', True), LifecycleState.ACTIVE)
        self.assertEqual(derive_lifecycle_state('approved', False), LifecycleState.DEACTIVATED)


class SoftDeleteViewTests(TestCase):
    def setUp(self):
        self.superuser = User.objects.create_superuser(
            username='root32', email='root32@example.com', password='Root123!x')
        self.client = APIClient()
        self.client.force_authenticate(self.superuser)

    def test_admin_delete_is_soft_and_preserves_audit(self):
        target = _user('deleteme', state=LifecycleState.ACTIVE, is_active=True)
        transition_user(target, LifecycleState.DEACTIVATED, reason='pre-existing history')
        prior_audit = UserLifecycleAudit.objects.filter(user=target).count()

        resp = self.client.delete(reverse('admin-user-delete', args=[target.id]))
        self.assertEqual(resp.status_code, 200, resp.content)

        # Row survives; tombstone set; audit trail intact + grew.
        target.refresh_from_db()
        profile = target.profile
        profile.refresh_from_db()
        self.assertEqual(profile.lifecycle_state, LifecycleState.DELETED)
        self.assertIsNotNone(profile.deleted_at)
        self.assertFalse(target.is_active)
        self.assertGreater(UserLifecycleAudit.objects.filter(user=target).count(), prior_audit)

    def test_admin_delete_pending_user_is_rejected(self):
        target = _user('pendingdel', state=LifecycleState.PENDING)
        resp = self.client.delete(reverse('admin-user-delete', args=[target.id]))
        self.assertEqual(resp.status_code, 409)
        self.assertTrue(User.objects.filter(id=target.id).exists())

    def test_admin_delete_twice_is_rejected(self):
        target = _user('twicedel', state=LifecycleState.ACTIVE, is_active=True)
        self.assertEqual(self.client.delete(reverse('admin-user-delete', args=[target.id])).status_code, 200)
        self.assertEqual(self.client.delete(reverse('admin-user-delete', args=[target.id])).status_code, 409)


class ReactivationViewTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user(
            username='staff32', email='staff32@example.com', password='Staff123!x',
            is_staff=True, is_active=True)
        self.client = APIClient()
        self.client.force_authenticate(self.staff)

    def _reactivate(self, user):
        return self.client.patch(reverse('admin-user-reactivate', args=[user.id]), {'reason': 'restore'})

    def test_reactivate_deactivated_user(self):
        target = _user('deact32', state=LifecycleState.DEACTIVATED)
        resp = self._reactivate(target)
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertEqual(resp.data['lifecycle_state'], LifecycleState.ACTIVE)
        target.refresh_from_db()
        self.assertTrue(target.is_active)
        audit = UserLifecycleAudit.objects.filter(user=target).latest('created_at')
        self.assertEqual((audit.from_state, audit.to_state, audit.outcome, audit.actor_id),
                         (LifecycleState.DEACTIVATED, LifecycleState.ACTIVE, 'applied', self.staff.id))

    def test_reactivate_denied_user(self):
        target = _user('denied32', state=LifecycleState.DENIED)
        resp = self._reactivate(target)
        self.assertEqual(resp.status_code, 200, resp.content)
        target.refresh_from_db()
        self.assertTrue(target.is_active)

    def test_reactivate_deleted_user_is_rejected(self):
        target = _user('deleted32', state=LifecycleState.DELETED)
        resp = self._reactivate(target)
        self.assertEqual(resp.status_code, 409)
        target.refresh_from_db()
        self.assertFalse(target.is_active)

    def test_reactivate_requires_staff(self):
        nonstaff = _user('nonstaff32', state=LifecycleState.ACTIVE, is_active=True)
        client = APIClient()
        client.force_authenticate(nonstaff)
        target = _user('target32', state=LifecycleState.DEACTIVATED)
        resp = client.patch(reverse('admin-user-reactivate', args=[target.id]), {})
        self.assertEqual(resp.status_code, 403)


class ApprovalFlowRegressionTests(TestCase):
    """Approve/deny still work (now via the FSM); pending list/count semantics unchanged."""

    def setUp(self):
        self.staff = User.objects.create_user(
            username='staffreg', email='staffreg@example.com', password='Staff123!x',
            is_staff=True, is_active=True)
        self.client = APIClient()
        self.client.force_authenticate(self.staff)

    def test_approve_pending_user_via_view(self):
        target = _user('appr32', state=LifecycleState.PENDING)
        with patch('identity.views.send_account_approved_email'):
            resp = self.client.patch(reverse('admin-user-approve', args=[target.id]), {'status': 'approved'})
        self.assertEqual(resp.status_code, 200, resp.content)
        target.refresh_from_db()
        profile = target.profile
        profile.refresh_from_db()
        self.assertTrue(target.is_active)
        self.assertEqual(profile.lifecycle_state, LifecycleState.ACTIVE)
        self.assertEqual(profile.approved_by_id, self.staff.id)

    def test_deny_pending_user_via_view(self):
        target = _user('deny32', state=LifecycleState.PENDING)
        with patch('identity.views.send_account_denied_email'):
            resp = self.client.patch(
                reverse('admin-user-approve', args=[target.id]),
                {'status': 'denied', 'review_note': 'nope'})
        self.assertEqual(resp.status_code, 200, resp.content)
        profile = target.profile
        profile.refresh_from_db()
        self.assertEqual(profile.lifecycle_state, LifecycleState.DENIED)

    def test_already_reviewed_still_400(self):
        target = _user('rev32', state=LifecycleState.ACTIVE, is_active=True)
        profile = target.profile
        profile.approval_status = 'approved'
        profile.save(update_fields=['approval_status'])
        resp = self.client.patch(reverse('admin-user-approve', args=[target.id]), {'status': 'approved'})
        self.assertEqual(resp.status_code, 400)

    def test_pending_count_semantics_unchanged(self):
        _user('p1of32', state=LifecycleState.PENDING)
        _user('p2of32', state=LifecycleState.PENDING)
        deleted = _user('p3of32', state=LifecycleState.ACTIVE, is_active=True)
        transition_user(deleted, LifecycleState.DELETED)

        pending = UserProfile.objects.filter(approval_status='pending').count()
        # The two pending users (deleted user synced to approved, not pending).
        self.assertEqual(
            UserProfile.objects.filter(approval_status='pending',
                                       user__username__in=['p1of32', 'p2of32']).count(), 2)
        self.assertNotIn(
            deleted.profile.id,
            UserProfile.objects.filter(approval_status='pending').values_list('id', flat=True))
        self.assertGreaterEqual(pending, 2)
