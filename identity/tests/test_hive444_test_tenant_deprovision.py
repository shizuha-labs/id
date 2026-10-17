"""HIVE-444: scoped test-tenant deprovision — non-superuser path, hard-gated.

The QA/validation runtime must be able to tear down its own throwaway test
tenants with a dedicated service credential, and the endpoint must be
constitutionally incapable of deleting a real user.
"""
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIRequestFactory

from identity.internal_urls import InternalTestTenantDeprovisionView
from identity.models import AdminAuditEvent

User = get_user_model()

TOKEN = 'test-validation-runtime-token'


@override_settings(VALIDATION_RUNTIME_TOKEN=TOKEN)
class TestTenantDeprovisionTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.view = InternalTestTenantDeprovisionView.as_view()

    def _call(self, user_id, token=TOKEN):
        headers = {'HTTP_X_VALIDATION_RUNTIME_TOKEN': token} if token is not None else {}
        request = self.factory.delete(
            f'/api/internal/test-tenants/{user_id}/deprovision/', **headers)
        return self.view(request, user_id=user_id)

    def _test_tenant(self, **overrides):
        defaults = dict(
            username='gp-goldpath-x',
            email='gp-goldpath-x@shizuha-test.local',
            password='x',
        )
        defaults.update(overrides)
        return User.objects.create_user(**defaults)

    def test_deprovisions_test_tenant_and_audits(self):
        user = self._test_tenant()
        response = self._call(user.id)
        self.assertEqual(response.status_code, 200)
        user.refresh_from_db()
        self.assertFalse(user.is_active)
        self.assertEqual(user.profile.lifecycle_state, 'deleted')
        self.assertTrue(response.data['identity_retained'])
        # Identity retention does not replace the hash-chained audit.
        event = AdminAuditEvent.objects.filter(action='test_tenant.deprovision').latest('seq')
        self.assertEqual(event.target_id, str(user.id))
        self.assertIn('shizuha-test.local', event.target_repr)

    def test_deprovisions_qa_fixture_domain_user(self):
        """HIVE-2697: the golden-path validator signs its throwaway users up
        on the QA fixture signup domain (HIVE-423), not @shizuha-test.local —
        the deprovision gate must accept that domain or every validation run
        leaves qafixture litter behind."""
        user = self._test_tenant(
            username='gp_goldpath_qa',
            email='gp_goldpath_qa@qafixture.shizuha.com',
        )
        with override_settings(QA_FIXTURE_SIGNUP_DOMAIN='qafixture.shizuha.com'):
            response = self._call(user.id)
        self.assertEqual(response.status_code, 200)
        user.refresh_from_db()
        self.assertFalse(user.is_active)
        self.assertEqual(user.profile.lifecycle_state, 'deleted')
        self.assertTrue(response.data['identity_retained'])
        event = AdminAuditEvent.objects.filter(action='test_tenant.deprovision').latest('seq')
        self.assertEqual(event.target_id, str(user.id))

    def test_qa_fixture_gate_is_inert_without_the_setting(self):
        """Refuse-by-default: with QA_FIXTURE_SIGNUP_DOMAIN unset, a
        qafixture-domain user is NOT deletable via this path."""
        user = self._test_tenant(
            username='gp_goldpath_qa2',
            email='gp_goldpath_qa2@qafixture.shizuha.com',
        )
        with override_settings(QA_FIXTURE_SIGNUP_DOMAIN=''):
            response = self._call(user.id)
        self.assertEqual(response.status_code, 403)
        self.assertTrue(User.objects.filter(id=user.id).exists())

    def test_refuses_real_domain_user(self):
        user = self._test_tenant(username='real', email='real@shizuha.com')
        response = self._call(user.id)
        self.assertEqual(response.status_code, 403)
        self.assertTrue(User.objects.filter(id=user.id).exists())

    def test_refuses_staff_and_superuser_even_on_test_domain(self):
        staff = self._test_tenant(username='st', email='st@shizuha-test.local', is_staff=True)
        boss = self._test_tenant(username='su', email='su@shizuha-test.local', is_superuser=True)
        self.assertEqual(self._call(staff.id).status_code, 403)
        self.assertEqual(self._call(boss.id).status_code, 403)
        self.assertEqual(User.objects.filter(id__in=[staff.id, boss.id]).count(), 2)

    def test_wrong_or_missing_token_forbidden(self):
        user = self._test_tenant()
        self.assertEqual(self._call(user.id, token='wrong').status_code, 403)
        self.assertEqual(self._call(user.id, token=None).status_code, 403)
        self.assertTrue(User.objects.filter(id=user.id).exists())

    @override_settings(VALIDATION_RUNTIME_TOKEN='')
    def test_unconfigured_token_is_503_not_open(self):
        user = self._test_tenant()
        self.assertEqual(self._call(user.id).status_code, 503)
        self.assertTrue(User.objects.filter(id=user.id).exists())

    def test_missing_user_404(self):
        self.assertEqual(self._call(999999).status_code, 404)


@override_settings(VALIDATION_RUNTIME_TOKEN=TOKEN, QA_FIXTURE_SIGNUP_DOMAIN='validation.example.test')
class SignupBillingDeprovisionTests(TestCase):
    def setUp(self):
        from django.core.cache import cache
        cache.clear()

    def test_actual_signup_cleanup_retains_billing_identity_and_grant(self):
        from unittest import mock
        from identity.models import BillingAccount, FreeTierGrant
        from rest_framework.test import APIClient
        client = APIClient()
        with mock.patch('identity.views._fetch_membership_projection', return_value=({}, [], {})):
            signup = client.post('/api/auth/register/', {
                'username': 'golden_retention_fixture',
                'email': 'golden-retention-fixture@validation.example.test',
                'password': 'SyntheticFixturePass123!',
                'password2': 'SyntheticFixturePass123!',
            }, format='json')
        self.assertEqual(signup.status_code, 201)
        user = User.objects.get(username='golden_retention_fixture')
        access, refresh = signup.data['tokens']['access'], signup.data['tokens']['refresh']
        client.credentials(HTTP_AUTHORIZATION='Bearer ' + access)
        self.assertEqual(client.get('/api/auth/profile/').status_code, 200)
        account = BillingAccount.objects.get(user=user)
        before_account = list(BillingAccount.objects.filter(pk=account.pk).values())
        before_grants = list(FreeTierGrant.objects.filter(account=account).values())
        self.assertEqual(len(before_grants), 1)
        response = client.delete(f'/api/internal/test-tenants/{user.pk}/deprovision/',
                                 HTTP_X_VALIDATION_RUNTIME_TOKEN=TOKEN)
        self.assertEqual(response.status_code, 200)
        user.refresh_from_db()
        self.assertFalse(user.is_active)
        self.assertEqual(user.profile.lifecycle_state, 'deleted')
        self.assertEqual(before_account, list(BillingAccount.objects.filter(pk=account.pk).values()))
        self.assertEqual(before_grants, list(FreeTierGrant.objects.filter(account=account).values()))
        self.assertEqual(response.data['lifecycle_state'], 'deleted')
        self.assertTrue(response.data['identity_retained'])
        self.assertEqual(client.get('/api/auth/profile/').status_code, 401)
        client.credentials()
        self.assertEqual(client.post('/api/auth/refresh/', {'refresh': refresh}, format='json').status_code, 401)
        self.assertEqual(client.post('/api/auth/login/', {
            'username': user.username, 'password': 'SyntheticFixturePass123!',
        }, format='json').status_code, 401)


    def _financial_rows(self):
        from identity.models import BillingAccount, FreeTierGrant, UpgradeInterest
        return {model.__name__: list(model.objects.order_by('pk').values())
                for model in (BillingAccount, FreeTierGrant, UpgradeInterest)}

    def _fixture(self, name, state='pending'):
        from identity.billing import ensure_free_v1_for_user
        from identity.lifecycle import LifecycleState, transition_user
        from identity.models import UpgradeInterest
        user = User.objects.create_user(username=name, email=name + '@validation.example.test',
                                        password='SyntheticFixturePass123!', is_active=False)
        account, _ = ensure_free_v1_for_user(user)
        UpgradeInterest.objects.create(account=account, source='id')
        if state == 'denied':
            transition_user(user, LifecycleState.DENIED, reason='synthetic fixture')
        elif state != 'pending':
            transition_user(user, LifecycleState.ACTIVE, reason='synthetic fixture')
            if state != 'active':
                transition_user(user, state, reason='synthetic fixture')
        return user

    def _delete(self, user):
        from rest_framework.test import APIClient
        return APIClient().delete(f'/api/internal/test-tenants/{user.pk}/deprovision/',
                                  HTTP_X_VALIDATION_RUNTIME_TOKEN=TOKEN)

    def test_every_legal_source_state_uses_terminal_lifecycle_and_keeps_all_financial_rows(self):
        from identity.models import UserLifecycleAudit
        unrelated = self._fixture('unrelated_financial_identity', 'active')
        unrelated_before = list(User.objects.filter(pk=unrelated.pk).values())
        for state in ('pending', 'active', 'deactivated', 'denied', 'deleted'):
            with self.subTest(state=state):
                user = self._fixture('cleanup_' + state, state)
                before = self._financial_rows()
                old_audits = set(UserLifecycleAudit.objects.filter(user=user).values_list('pk', flat=True))
                response = self._delete(user)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.data['already_deprovisioned'], state == 'deleted')
                user.refresh_from_db()
                self.assertFalse(user.is_active)
                self.assertEqual(user.profile.lifecycle_state, 'deleted')
                self.assertIsNotNone(user.profile.access_revoked_before)
                self.assertEqual(before, self._financial_rows())
                self.assertEqual(unrelated_before, list(User.objects.filter(pk=unrelated.pk).values()))
                edges = list(UserLifecycleAudit.objects.filter(user=user).exclude(pk__in=old_audits)
                             .order_by('pk').values_list('to_state', 'reason'))
                self.assertEqual([edge[0] for edge in edges],
                                 ['denied', 'deleted'] if state == 'pending' else [] if state == 'deleted' else ['deleted'])
                self.assertTrue(all('validation-runtime cleanup:' in edge[1] for edge in edges))

    def test_agent_is_refused_even_with_test_domain_and_preserves_billing(self):
        user = self._fixture('protected_agent_fixture')
        profile = user.profile
        profile.account_type = 'agent'
        profile.save(update_fields=['account_type'])
        before = self._financial_rows()
        self.assertEqual(self._delete(user).status_code, 403)
        self.assertEqual(before, self._financial_rows())
        user.refresh_from_db()
        self.assertEqual(user.profile.lifecycle_state, 'pending')

    def test_pending_deny_and_terminal_delete_are_one_transaction_on_revocation_failure(self):
        from unittest import mock
        from identity.models import UserLifecycleAudit, UserLifecycleEvent
        user = self._fixture('rollback_pending_fixture')
        before = self._financial_rows()
        with mock.patch('identity.views.revoke_all_user_tokens', side_effect=RuntimeError('synthetic revocation failure')):
            with self.assertRaisesRegex(RuntimeError, 'synthetic revocation failure'):
                self._delete(user)
        user.refresh_from_db()
        self.assertFalse(user.is_active)
        self.assertEqual(user.profile.lifecycle_state, 'pending')
        self.assertIsNone(user.profile.access_revoked_before)
        self.assertEqual(UserLifecycleAudit.objects.filter(user=user).count(), 0)
        self.assertEqual(UserLifecycleEvent.objects.filter(user_id=user.pk).count(), 0)
        self.assertEqual(before, self._financial_rows())
        self.assertFalse(AdminAuditEvent.objects.filter(action='test_tenant.deprovision', target_id=str(user.pk)).exists())

    def test_final_audit_failure_rolls_back_lifecycle_outbox_and_real_token_revocation(self):
        from unittest import mock
        from identity.views import get_tokens_for_user
        from identity.models import UserLifecycleAudit, UserLifecycleEvent
        from rest_framework.test import APIClient
        from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken
        user = self._fixture('rollback_active_fixture', 'active')
        with mock.patch('identity.views._fetch_membership_projection', return_value=({}, [], {})):
            tokens = get_tokens_for_user(user)
        user.refresh_from_db()
        probe = APIClient()
        probe.credentials(HTTP_AUTHORIZATION='Bearer ' + tokens['access'])
        self.assertEqual(probe.get('/api/auth/profile/').status_code, 200)
        old_version = user.profile.token_version
        before = self._financial_rows()
        audit_count = UserLifecycleAudit.objects.filter(user=user).count()
        event_count = UserLifecycleEvent.objects.filter(user_id=user.pk).count()
        blacklist_count = BlacklistedToken.objects.count()
        with mock.patch.object(AdminAuditEvent.objects, 'append', side_effect=RuntimeError('synthetic audit failure')):
            with self.assertRaisesRegex(RuntimeError, 'synthetic audit failure'):
                self._delete(user)
        user.refresh_from_db()
        self.assertTrue(user.is_active)
        self.assertEqual(user.profile.lifecycle_state, 'active')
        self.assertEqual(user.profile.token_version, old_version)
        self.assertIsNone(user.profile.access_revoked_before)
        self.assertEqual(UserLifecycleAudit.objects.filter(user=user).count(), audit_count)
        self.assertEqual(UserLifecycleEvent.objects.filter(user_id=user.pk).count(), event_count)
        self.assertEqual(BlacklistedToken.objects.count(), blacklist_count)
        self.assertEqual(before, self._financial_rows())
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='Bearer ' + tokens['access'])
        self.assertEqual(client.get('/api/auth/profile/').status_code, 200)
        client.credentials()
        with mock.patch('identity.views._fetch_membership_projection', return_value=({}, [], {})):
            self.assertEqual(client.post('/api/auth/refresh/', {'refresh': tokens['refresh']}, format='json').status_code, 200)

    def test_inconsistent_deleted_state_does_not_claim_successful_cleanup(self):
        user = self._fixture('unproven_deleted_fixture')
        profile = user.profile
        profile.lifecycle_state = 'deleted'
        profile.save(update_fields=['lifecycle_state'])
        before = self._financial_rows()
        self.assertEqual(self._delete(user).status_code, 409)
        self.assertEqual(before, self._financial_rows())
