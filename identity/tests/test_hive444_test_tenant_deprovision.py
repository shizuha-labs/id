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
        self.assertFalse(User.objects.filter(id=user.id).exists())
        # The deprovision is recorded in the hash-chained ledger, which
        # survives the user-row cascade.
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
        self.assertFalse(User.objects.filter(id=user.id).exists())
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
