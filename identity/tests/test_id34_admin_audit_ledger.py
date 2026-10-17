"""ID-34 (HLD ID-5): tamper-evident admin audit ledger + mutation wrappers.

Proves: (1) every privileged admin mutation wrapper emits a complete
AdminAuditEvent; (2) events form a verifiable hash chain and in-place
tampering / row deletion breaks verification at the right event; (3) the
ORM layer is append-only; (4) a failed audit write rolls the privileged
mutation back (no silent unaudited mutation); (5) the admin endpoints
route through the wrappers rather than mutating directly.
"""
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIRequestFactory, force_authenticate

from identity.admin_audit import (
    ACTION_ACCESS_REQUEST_REVIEW,
    ACTION_ADMIN_SET_PASSWORD,
    ACTION_ADMIN_USER_CREATE,
    ACTION_ADMIN_USER_DELETE,
    ACTION_ADMIN_USER_UPDATE,
    ACTION_DJANGO_ADMIN_MUTATION,
    ACTION_SERVICE_CATALOG_UPDATE,
    ACTION_USER_ACCOUNT_REVIEW,
    ACTION_USER_SERVICES_GRANT,
    ACTION_USER_SERVICES_REVOKE,
    audited_access_request_review,
    audited_admin_set_password,
    audited_admin_user_create,
    audited_admin_user_delete,
    audited_admin_user_update,
    audited_service_catalog_update,
    audited_user_approval,
    audited_user_services_change,
    verify_chain,
)
from identity.models import (
    ADMIN_AUDIT_GENESIS_HASH,
    AdminAuditEvent,
    ServiceAccessRequest,
    Tool,
    UserProfile,
)
from identity.internal_urls import (
    AdminUserCreateView,
    AdminUserDeleteView,
    AdminUserUpdateView,
)
from identity.views import (
    AdminAccessRequestReviewView,
    AdminServiceUpdateView,
    AdminSetPasswordView,
    AdminUserServicesView,
    UserApprovalView,
)

User = get_user_model()


class AdminAuditBase(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user(
            username='admin', password='pw', email='admin@shizuha.com',
            is_staff=True, is_superuser=True,
        )
        self.target = User.objects.create_user(
            username='alice', password='old-password-1', email='alice@shizuha.com',
        )
        # ID-32: these fixtures represent existing approved active users; the
        # soft-delete FSM intentionally rejects pending -> deleted.
        for user in (self.admin, self.target):
            UserProfile.objects.update_or_create(
                user=user,
                defaults={'approval_status': 'approved', 'lifecycle_state': 'active'},
            )
        self.tool = Tool.objects.create(
            slug='ledgertool', display_name='Ledger Tool', requires_approval=True,
            is_default_enabled=False,
        )


class WrapperEmissionTests(AdminAuditBase):
    """Each wrapper emits one complete audit event and the chain verifies."""

    def test_service_catalog_update_emits_event(self):
        audited_service_catalog_update(
            actor=self.admin, tool=self.tool,
            changes={'is_active': False, 'requires_approval': False},
        )
        event = AdminAuditEvent.objects.get()
        self.assertEqual(event.action, ACTION_SERVICE_CATALOG_UPDATE)
        self.assertEqual(event.actor_id, self.admin.id)
        self.assertEqual(event.actor_username, 'admin')
        self.assertEqual(event.target_type, 'tool')
        self.assertEqual(event.target_id, 'ledgertool')
        self.assertEqual(event.before, {'is_active': True, 'requires_approval': True})
        self.assertEqual(event.after, {'is_active': False, 'requires_approval': False})
        self.tool.refresh_from_db()
        self.assertFalse(self.tool.is_active)
        self.assertTrue(verify_chain().ok)

    def test_grant_and_revoke_emit_events(self):
        audited_user_services_change(
            actor=self.admin, user=self.target, tools=[self.tool], action='grant',
        )
        audited_user_services_change(
            actor=self.admin, user=self.target, tools=[self.tool], action='revoke',
        )
        grant, revoke = AdminAuditEvent.objects.order_by('seq')
        self.assertEqual(grant.action, ACTION_USER_SERVICES_GRANT)
        self.assertEqual(grant.target_type, 'user')
        self.assertEqual(grant.target_id, str(self.target.id))
        self.assertIn('ledgertool', grant.after['enabled_services'])
        self.assertEqual(revoke.action, ACTION_USER_SERVICES_REVOKE)
        self.assertIn('ledgertool', revoke.before['enabled_services'])
        self.assertNotIn('ledgertool', revoke.after['enabled_services'])
        self.assertTrue(verify_chain().ok)

    def test_access_request_review_approval_emits_event_and_grants(self):
        req = ServiceAccessRequest.objects.create(user=self.target, tool=self.tool)
        audited_access_request_review(
            actor=self.admin, access_request=req, new_status='approved',
            review_note='ok',
        )
        event = AdminAuditEvent.objects.get()
        self.assertEqual(event.action, ACTION_ACCESS_REQUEST_REVIEW)
        self.assertEqual(event.before['status'], 'pending')
        self.assertEqual(event.after['status'], 'approved')
        self.assertTrue(event.after['tool_granted'])
        req.refresh_from_db()
        self.assertEqual(req.status, 'approved')
        self.assertEqual(req.reviewed_by_id, self.admin.id)
        profile = UserProfile.objects.get(user=self.target)
        self.assertIn('ledgertool', profile.enabled_tools.values_list('slug', flat=True))

    def test_access_request_review_denial_emits_event_without_grant(self):
        req = ServiceAccessRequest.objects.create(user=self.target, tool=self.tool)
        audited_access_request_review(
            actor=self.admin, access_request=req, new_status='denied',
        )
        event = AdminAuditEvent.objects.get()
        self.assertEqual(event.after['status'], 'denied')
        self.assertFalse(event.after['tool_granted'])

    def test_user_approval_emits_event(self):
        pending = User.objects.create_user(
            username='pending', password='pw', email='p@shizuha.com', is_active=False,
        )
        profile, _ = UserProfile.objects.update_or_create(
            user=pending, defaults={'approval_status': 'pending'},
        )
        audited_user_approval(
            actor=self.admin, user=pending, profile=profile,
            new_status='approved', review_note='welcome',
        )
        event = AdminAuditEvent.objects.get()
        self.assertEqual(event.action, ACTION_USER_ACCOUNT_REVIEW)
        self.assertEqual(event.before['approval_status'], 'pending')
        self.assertFalse(event.before['is_active'])
        self.assertEqual(event.after['approval_status'], 'approved')
        self.assertTrue(event.after['is_active'])
        pending.refresh_from_db()
        self.assertTrue(pending.is_active)

    def test_user_denial_emits_event(self):
        pending = User.objects.create_user(
            username='pending2', password='pw', email='p2@shizuha.com', is_active=False,
        )
        profile, _ = UserProfile.objects.update_or_create(
            user=pending, defaults={'approval_status': 'pending'},
        )
        audited_user_approval(
            actor=self.admin, user=pending, profile=profile, new_status='denied',
        )
        event = AdminAuditEvent.objects.get()
        self.assertEqual(event.after['approval_status'], 'denied')
        self.assertFalse(event.after['is_active'])

    def test_admin_set_password_emits_event_without_password_material(self):
        audited_admin_set_password(
            actor=self.admin, user=self.target, new_password='new-password-2',
        )
        event = AdminAuditEvent.objects.get()
        self.assertEqual(event.action, ACTION_ADMIN_SET_PASSWORD)
        self.assertEqual(event.after, {'password_changed': True})
        # No password material anywhere in the event payload.
        self.assertNotIn('new-password-2', event.hash_payload())
        self.target.refresh_from_db()
        self.assertTrue(self.target.check_password('new-password-2'))


class AdminUserMutationWrapperTests(AdminAuditBase):
    """Review P1: superuser admin user create/update/delete are audited."""

    def test_admin_user_create_emits_event_without_password_material(self):
        user = audited_admin_user_create(
            actor=self.admin, username='newstaff', email='ns@shizuha.com',
            password='fresh-password-3', is_staff=True, is_superuser=True,
        )
        event = AdminAuditEvent.objects.get()
        self.assertEqual(event.action, ACTION_ADMIN_USER_CREATE)
        self.assertEqual(event.target_id, str(user.id))
        self.assertEqual(event.after['is_staff'], True)
        self.assertEqual(event.after['is_superuser'], True)
        self.assertEqual(event.after['approval_status'], 'approved')
        self.assertNotIn('fresh-password-3', event.hash_payload())
        self.assertTrue(user.is_superuser)
        self.assertEqual(
            UserProfile.objects.get(user=user).approval_status, 'approved',
        )

    def test_admin_user_create_rolled_back_when_audit_fails(self):
        with mock.patch.object(
            AdminAuditEvent.objects, 'append', side_effect=RuntimeError('sink down'),
        ):
            with self.assertRaises(RuntimeError):
                audited_admin_user_create(
                    actor=self.admin, username='ghost', email='g@shizuha.com',
                    password='fresh-password-3', is_superuser=True,
                )
        self.assertFalse(User.objects.filter(username='ghost').exists())
        self.assertEqual(AdminAuditEvent.objects.count(), 0)

    def test_admin_user_update_emits_field_level_event(self):
        audited_admin_user_update(
            actor=self.admin, user=self.target,
            changes={'is_staff': True, 'is_superuser': True},
            new_password='rotated-pass-4',
        )
        event = AdminAuditEvent.objects.get()
        self.assertEqual(event.action, ACTION_ADMIN_USER_UPDATE)
        self.assertEqual(event.before, {'is_staff': False, 'is_superuser': False})
        self.assertEqual(event.after, {
            'is_staff': True, 'is_superuser': True, 'password_changed': True,
        })
        self.assertNotIn('rotated-pass-4', event.hash_payload())
        self.target.refresh_from_db()
        self.assertTrue(self.target.is_superuser)
        self.assertTrue(self.target.check_password('rotated-pass-4'))

    def test_admin_user_update_rolled_back_when_audit_fails(self):
        with mock.patch.object(
            AdminAuditEvent.objects, 'append', side_effect=RuntimeError('sink down'),
        ):
            with self.assertRaises(RuntimeError):
                audited_admin_user_update(
                    actor=self.admin, user=self.target,
                    changes={'is_superuser': True}, new_password='rotated-pass-4',
                )
        self.target.refresh_from_db()
        self.assertFalse(self.target.is_superuser)
        self.assertTrue(self.target.check_password('old-password-1'))
        self.assertEqual(AdminAuditEvent.objects.count(), 0)

    def test_admin_user_delete_emits_snapshot_event(self):
        target_id = self.target.id
        audited_admin_user_delete(actor=self.admin, user=self.target)
        event = AdminAuditEvent.objects.get()
        self.assertEqual(event.action, ACTION_ADMIN_USER_DELETE)
        self.assertEqual(event.target_id, str(target_id))
        self.assertEqual(event.before['username'], 'alice')
        self.assertTrue(event.after['deleted'])
        self.assertTrue(event.after['soft_deleted'])
        self.assertTrue(User.objects.filter(id=target_id).exists())
        profile = UserProfile.objects.get(user_id=target_id)
        self.assertEqual(profile.lifecycle_state, 'deleted')
        self.assertIsNotNone(profile.deleted_at)

    def test_admin_user_delete_rolled_back_when_audit_fails(self):
        # Capture the pk first: Model.delete() nulls the in-memory pk even
        # when the surrounding transaction rolls the row back.
        target_id = self.target.id
        with mock.patch.object(
            AdminAuditEvent.objects, 'append', side_effect=RuntimeError('sink down'),
        ):
            with self.assertRaises(RuntimeError):
                audited_admin_user_delete(actor=self.admin, user=self.target)
        self.assertTrue(User.objects.filter(id=target_id).exists())
        self.assertEqual(AdminAuditEvent.objects.count(), 0)


class HashChainTests(AdminAuditBase):
    def _emit(self, n):
        for i in range(n):
            AdminAuditEvent.objects.append(
                action=ACTION_SERVICE_CATALOG_UPDATE, actor=self.admin,
                target_type='tool', target_id=f't{i}', after={'i': i},
            )

    def test_chain_links_from_genesis(self):
        self._emit(3)
        first, second, third = AdminAuditEvent.objects.order_by('seq')
        self.assertEqual(first.prev_hash, ADMIN_AUDIT_GENESIS_HASH)
        self.assertEqual(second.prev_hash, first.event_hash)
        self.assertEqual(third.prev_hash, second.event_hash)
        result = verify_chain()
        self.assertTrue(result.ok)
        self.assertEqual(result.checked, 3)

    def test_payload_tamper_detected(self):
        self._emit(3)
        victim = AdminAuditEvent.objects.get(seq=2)
        # Bypass the append-only ORM guard the way an attacker with DB access
        # would — a raw queryset update.
        AdminAuditEvent.objects.filter(pk=victim.pk).update(after={'i': 999})
        result = verify_chain()
        self.assertFalse(result.ok)
        self.assertEqual(result.first_bad_seq, 2)
        self.assertIn('does not match its recorded hash', result.reason)

    def test_rehash_without_relink_detected(self):
        self._emit(3)
        victim = AdminAuditEvent.objects.get(seq=2)
        victim.after = {'i': 999}
        forged = victim.compute_hash()
        AdminAuditEvent.objects.filter(pk=victim.pk).update(
            after={'i': 999}, event_hash=forged,
        )
        # The forged row self-verifies, but event 3 no longer links to it.
        result = verify_chain()
        self.assertFalse(result.ok)
        self.assertEqual(result.first_bad_seq, 3)
        self.assertIn('prev_hash', result.reason)

    def test_row_deletion_detected(self):
        self._emit(3)
        # Model.delete() is blocked; a bulk queryset delete bypasses it the
        # way direct DB access would.
        AdminAuditEvent.objects.filter(seq=2).delete()
        result = verify_chain()
        self.assertFalse(result.ok)
        self.assertEqual(result.first_bad_seq, 3)
        self.assertIn('sequence gap', result.reason)

    def test_append_only_orm_guards(self):
        self._emit(1)
        event = AdminAuditEvent.objects.get()
        event.action = 'forged'
        with self.assertRaises(ValueError):
            event.save()
        with self.assertRaises(ValueError):
            event.delete()


class AtomicityTests(AdminAuditBase):
    """A failed audit append rolls back the privileged mutation."""

    def test_catalog_update_rolled_back_when_audit_fails(self):
        with mock.patch.object(
            AdminAuditEvent.objects, 'append', side_effect=RuntimeError('sink down'),
        ):
            with self.assertRaises(RuntimeError):
                audited_service_catalog_update(
                    actor=self.admin, tool=self.tool, changes={'is_active': False},
                )
        self.tool.refresh_from_db()
        self.assertTrue(self.tool.is_active)
        self.assertEqual(AdminAuditEvent.objects.count(), 0)

    def test_password_change_rolled_back_when_audit_fails(self):
        with mock.patch.object(
            AdminAuditEvent.objects, 'append', side_effect=RuntimeError('sink down'),
        ):
            with self.assertRaises(RuntimeError):
                audited_admin_set_password(
                    actor=self.admin, user=self.target, new_password='new-password-2',
                )
        self.target.refresh_from_db()
        self.assertTrue(self.target.check_password('old-password-1'))
        self.assertEqual(AdminAuditEvent.objects.count(), 0)

    def test_grant_rolled_back_when_audit_fails(self):
        with mock.patch.object(
            AdminAuditEvent.objects, 'append', side_effect=RuntimeError('sink down'),
        ):
            with self.assertRaises(RuntimeError):
                audited_user_services_change(
                    actor=self.admin, user=self.target, tools=[self.tool],
                    action='grant',
                )
        profile = UserProfile.objects.get(user=self.target)
        self.assertNotIn('ledgertool', profile.enabled_tools.values_list('slug', flat=True))
        self.assertEqual(AdminAuditEvent.objects.count(), 0)


class EndpointRoutingTests(AdminAuditBase):
    """The admin endpoints route through the wrappers (no direct-mutation bypass)."""

    def setUp(self):
        super().setUp()
        self.factory = APIRequestFactory()

    def _one_event(self, action):
        event = AdminAuditEvent.objects.get()
        self.assertEqual(event.action, action)
        self.assertEqual(event.actor_id, self.admin.id)
        self.assertTrue(verify_chain().ok)
        return event

    def test_admin_service_update_endpoint_audited(self):
        req = self.factory.patch(
            '/admin/services/ledgertool/', {'is_active': False}, format='json',
        )
        force_authenticate(req, user=self.admin)
        resp = AdminServiceUpdateView.as_view()(req, slug='ledgertool')
        self.assertEqual(resp.status_code, 200)
        event = self._one_event(ACTION_SERVICE_CATALOG_UPDATE)
        self.assertEqual(event.request_metadata['method'], 'PATCH')
        # Settings may add a script prefix (FORCE_SCRIPT_NAME) to the path.
        self.assertTrue(
            event.request_metadata['path'].endswith('/admin/services/ledgertool/'),
            event.request_metadata['path'],
        )

    def test_admin_user_services_endpoint_audited(self):
        req = self.factory.post(
            f'/admin/users/{self.target.id}/services/',
            {'service_slugs': ['ledgertool'], 'action': 'grant'}, format='json',
        )
        force_authenticate(req, user=self.admin)
        resp = AdminUserServicesView.as_view()(req, user_id=self.target.id)
        self.assertEqual(resp.status_code, 200)
        self.assertIn('ledgertool', resp.data['enabled_services'])
        self._one_event(ACTION_USER_SERVICES_GRANT)

    def test_access_request_review_endpoint_audited(self):
        access_req = ServiceAccessRequest.objects.create(user=self.target, tool=self.tool)
        req = self.factory.patch(
            f'/admin/requests/{access_req.id}/',
            {'status': 'approved'}, format='json',
        )
        force_authenticate(req, user=self.admin)
        resp = AdminAccessRequestReviewView.as_view()(req, pk=access_req.id)
        self.assertEqual(resp.status_code, 200)
        self._one_event(ACTION_ACCESS_REQUEST_REVIEW)

    @mock.patch('identity.views.send_account_approved_email')
    def test_user_approval_endpoint_audited(self, _mail):
        pending = User.objects.create_user(
            username='pending3', password='pw', email='p3@shizuha.com', is_active=False,
        )
        UserProfile.objects.update_or_create(
            user=pending, defaults={'approval_status': 'pending'},
        )
        req = self.factory.patch(
            f'/admin/users/{pending.id}/approve/',
            {'status': 'approved'}, format='json',
        )
        force_authenticate(req, user=self.admin)
        resp = UserApprovalView.as_view()(req, user_id=pending.id)
        self.assertEqual(resp.status_code, 200)
        self._one_event(ACTION_USER_ACCOUNT_REVIEW)

    def test_admin_set_password_endpoint_audited(self):
        req = self.factory.post(
            f'/admin/users/{self.target.id}/set-password/',
            {'password': 'brand-new-pass-9'}, format='json',
        )
        force_authenticate(req, user=self.admin)
        resp = AdminSetPasswordView.as_view()(req, user_id=self.target.id)
        self.assertEqual(resp.status_code, 200)
        self._one_event(ACTION_ADMIN_SET_PASSWORD)
        self.target.refresh_from_db()
        self.assertTrue(self.target.check_password('brand-new-pass-9'))

    # Review P1: the internal superuser admin user endpoints route through the
    # wrappers too (no ledger bypass on create/update/delete).
    def test_internal_admin_user_create_endpoint_audited(self):
        req = self.factory.post('/admin/users/create/', {
            'username': 'created', 'email': 'c@shizuha.com',
            'password': 'Str0ng-created-pass', 'is_staff': True,
        }, format='json')
        force_authenticate(req, user=self.admin)
        resp = AdminUserCreateView.as_view()(req)
        self.assertEqual(resp.status_code, 201)
        event = self._one_event(ACTION_ADMIN_USER_CREATE)
        self.assertEqual(event.after['is_staff'], True)
        self.assertNotIn('Str0ng-created-pass', event.hash_payload())

    def test_internal_admin_user_update_endpoint_audited(self):
        req = self.factory.patch(
            f'/admin/users/{self.target.id}/',
            {'is_superuser': True, 'password': 'Str0ng-updated-pass'}, format='json',
        )
        force_authenticate(req, user=self.admin)
        resp = AdminUserUpdateView.as_view()(req, user_id=self.target.id)
        self.assertEqual(resp.status_code, 200)
        event = self._one_event(ACTION_ADMIN_USER_UPDATE)
        self.assertEqual(event.after['is_superuser'], True)
        self.assertTrue(event.after['password_changed'])
        self.target.refresh_from_db()
        self.assertTrue(self.target.is_superuser)
        self.assertTrue(self.target.check_password('Str0ng-updated-pass'))

    def test_internal_admin_user_delete_endpoint_audited(self):
        target_id = self.target.id
        req = self.factory.delete(f'/admin/users/{target_id}/delete/')
        force_authenticate(req, user=self.admin)
        resp = AdminUserDeleteView.as_view()(req, user_id=target_id)
        self.assertEqual(resp.status_code, 200)
        event = self._one_event(ACTION_ADMIN_USER_DELETE)
        self.assertEqual(event.target_id, str(target_id))
        self.assertTrue(User.objects.filter(id=target_id).exists())
        self.assertEqual(UserProfile.objects.get(user_id=target_id).lifecycle_state, 'deleted')


class DjangoAdminSurfaceTests(AdminAuditBase):
    """Review P2: the Django admin mutation surface for Tool/UserProfile is
    audited, and the ledger itself is read-only in Django admin."""

    def test_tool_admin_save_model_emits_event(self):
        from django.contrib import admin as django_admin
        from identity.admin import ToolAdmin

        model_admin = ToolAdmin(Tool, django_admin.site)
        req = APIRequestFactory().post('/django-admin/identity/tool/')
        req.user = self.admin
        form = mock.Mock(changed_data=['is_active'])
        self.tool.is_active = False
        model_admin.save_model(req, self.tool, form, change=True)
        event = AdminAuditEvent.objects.get()
        self.assertEqual(event.action, ACTION_DJANGO_ADMIN_MUTATION)
        self.assertEqual(event.target_type, 'tool')
        self.assertEqual(event.after, {'changed_fields': ['is_active']})
        self.assertTrue(verify_chain().ok)

    def test_tool_admin_delete_model_emits_event(self):
        from django.contrib import admin as django_admin
        from identity.admin import ToolAdmin

        model_admin = ToolAdmin(Tool, django_admin.site)
        req = APIRequestFactory().post('/django-admin/identity/tool/')
        req.user = self.admin
        model_admin.delete_model(req, self.tool)
        event = AdminAuditEvent.objects.get()
        self.assertEqual(event.action, ACTION_DJANGO_ADMIN_MUTATION)
        self.assertTrue(event.after['deleted'])
        self.assertFalse(Tool.objects.filter(slug='ledgertool').exists())

    def test_tool_admin_bulk_delete_rolls_back_when_audit_fails(self):
        from django.contrib import admin as django_admin
        from identity.admin import ToolAdmin

        model_admin = ToolAdmin(Tool, django_admin.site)
        req = APIRequestFactory().post('/django-admin/identity/tool/')
        req.user = self.admin
        with mock.patch.object(
            AdminAuditEvent.objects, 'append', side_effect=RuntimeError('sink down'),
        ):
            with self.assertRaises(RuntimeError):
                model_admin.delete_queryset(
                    req, Tool.objects.filter(slug='ledgertool'),
                )
        self.assertTrue(Tool.objects.filter(slug='ledgertool').exists())
        self.assertEqual(AdminAuditEvent.objects.count(), 0)

    def test_ledger_is_read_only_in_django_admin(self):
        from django.contrib import admin as django_admin
        from identity.admin import AdminAuditEventAdmin

        model_admin = AdminAuditEventAdmin(AdminAuditEvent, django_admin.site)
        req = APIRequestFactory().get('/django-admin/identity/adminauditevent/')
        req.user = self.admin
        self.assertFalse(model_admin.has_add_permission(req))
        self.assertFalse(model_admin.has_change_permission(req))
        self.assertFalse(model_admin.has_delete_permission(req))
