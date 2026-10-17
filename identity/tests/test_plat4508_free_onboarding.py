from concurrent.futures import ThreadPoolExecutor
from unittest import mock

from django.contrib.auth import get_user_model
from django.db import close_old_connections
from django.test import TestCase, TransactionTestCase, override_settings
from rest_framework.test import APIClient

from identity.billing import ensure_free_v1_for_user
from identity.models import BillingAccount, FreeTierGrant, UpgradeInterest


User = get_user_model()
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


class SignupProvisioningTests(TestCase):
    def test_standard_signup_creates_one_account_and_free_v1_grant(self):
        response = self.client.post('/api/auth/register/', {
            'username': 'free_signup',
            'email': 'free-signup@example.com',
            'password': 'StrongSignupPass123!',
            'password2': 'StrongSignupPass123!',
        }, content_type='application/json')

        self.assertEqual(response.status_code, 201)
        self.assertTrue(response.json()['pending_approval'])
        account = BillingAccount.objects.get(user__username='free_signup')
        self.assertEqual(response.json()['billing_account']['account_id'], str(account.account_id))
        self.assertEqual(account.subject_key, f'user:{account.user_id}')
        self.assertEqual(
            FreeTierGrant.objects.get(account=account).plan_code,
            'free-v1',
        )

        replay = self.client.post('/api/auth/register/', {
            'username': 'free_signup',
            'email': 'free-signup@example.com',
            'password': 'StrongSignupPass123!',
            'password2': 'StrongSignupPass123!',
        }, content_type='application/json')
        self.assertEqual(replay.status_code, 400)
        self.assertEqual(BillingAccount.objects.filter(user__username='free_signup').count(), 1)
        self.assertEqual(FreeTierGrant.objects.filter(account=account).count(), 1)

    @override_settings(ALLOW_DRIVE_SELFREGISTRATION=True)
    def test_active_self_signup_returns_same_server_account(self):
        response = self.client.post('/api/auth/register/', {
            'username': 'free_drive',
            'email': 'free-drive@example.com',
            'password': 'StrongSignupPass123!',
            'password2': 'StrongSignupPass123!',
            'intent': 'drive',
        }, content_type='application/json')
        self.assertEqual(response.status_code, 201)
        account = BillingAccount.objects.get(user__username='free_drive')
        self.assertEqual(response.json()['billing_account']['account_id'], str(account.account_id))
        self.assertEqual(response.json()['billing_account']['grant']['plan'], 'free-v1')


class BillingAccountApiTests(TestCase):
    def setUp(self):
        self.alice = User.objects.create_user(
            username='billing-alice', email='billing-alice@example.com', password='TestPass123!',
        )
        self.bob = User.objects.create_user(
            username='billing-bob', email='billing-bob@example.com', password='TestPass123!',
        )
        self.alice_account, _ = ensure_free_v1_for_user(self.alice)
        self.bob_account, _ = ensure_free_v1_for_user(self.bob)
        self.client = APIClient()
        self.client.force_authenticate(self.alice)

    def test_account_read_is_caller_scoped_and_lazily_repairs_grant(self):
        FreeTierGrant.objects.filter(account=self.alice_account).delete()
        response = self.client.get('/api/auth/billing/account/', {
            'account_id': str(self.bob_account.account_id),
            'organization_id': 999,
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data['billing_account']['account_id'],
            str(self.alice_account.account_id),
        )
        self.assertNotEqual(
            response.data['billing_account']['account_id'],
            str(self.bob_account.account_id),
        )
        self.assertEqual(response.data['billing_account']['grant']['plan'], 'free-v1')
        self.assertEqual(response.data['payment_provider'], 'mock')
        self.assertFalse(response.data['checkout_available'])

    def test_notify_interest_rejects_organization_selector(self):
        response = self.client.post('/api/auth/billing/upgrade-interest/', {
            'source': 'scs',
            'meter': 'storage.bytes',
            'organization_id': 999,
        }, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertFalse(UpgradeInterest.objects.exists())

    def test_notify_interest_is_idempotent_mock_only_and_rejects_payer_selector(self):
        injected = self.client.post('/api/auth/billing/upgrade-interest/', {
            'source': 'cortex',
            'meter': 'inference.weighted_tokens',
            'account_id': str(self.bob_account.account_id),
        }, format='json')
        self.assertEqual(injected.status_code, 400)
        self.assertFalse(UpgradeInterest.objects.exists())

        payload = {
            'source': 'cortex',
            'meter': 'inference.weighted_tokens',
            'target_plan': 'starter-999-v1-rc1',
        }
        first = self.client.post('/api/auth/billing/upgrade-interest/', payload, format='json')
        replay = self.client.post('/api/auth/billing/upgrade-interest/', payload, format='json')
        self.assertEqual(first.status_code, 201)
        self.assertEqual(replay.status_code, 200)
        self.assertTrue(first.data['created'])
        self.assertFalse(replay.data['created'])
        self.assertFalse(replay.data['checkout_created'])
        self.assertEqual(replay.data['payment_provider'], 'mock')
        self.assertEqual(UpgradeInterest.objects.get().account, self.alice_account)

    def test_notify_interest_context_is_allowlisted_and_storage_is_bounded(self):
        valid = self.client.post('/api/auth/billing/upgrade-interest/', {
            'source': 'cortex',
            'meter': 'inference.weighted_tokens',
        }, format='json')
        self.assertEqual(valid.status_code, 201)

        # A different supported display context updates the one plan interest;
        # it can never allocate another row for the same account and plan.
        updated = self.client.post('/api/auth/billing/upgrade-interest/', {
            'source': 'scs',
            'meter': 'compute.cpu_millisecond_seconds',
        }, format='json')
        self.assertEqual(updated.status_code, 200)
        interest = UpgradeInterest.objects.get()
        self.assertEqual((interest.source, interest.meter), (
            'scs', 'compute.cpu_millisecond_seconds',
        ))

        for index in range(40):
            rejected = self.client.post('/api/auth/billing/upgrade-interest/', {
                'source': f'attacker-{index}',
                'meter': f'arbitrary.meter.{index}',
            }, format='json')
            self.assertEqual(rejected.status_code, 400)
        self.assertEqual(UpgradeInterest.objects.count(), 1)

    def test_notify_interest_rejects_source_beyond_schema_boundary(self):
        response = self.client.post('/api/auth/billing/upgrade-interest/', {
            'source': 'x' * 33,
            'meter': '',
        }, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data, {'error': 'invalid source'})
        self.assertFalse(UpgradeInterest.objects.exists())


class BillingAccountConcurrencyTests(TransactionTestCase):
    reset_sequences = True

    def test_concurrent_signup_creates_one_user_account_and_grant(self):
        payload = {
            'username': 'billing_signup_race',
            'email': 'billing-signup-race@example.com',
            'password': 'StrongSignupPass123!',
            'password2': 'StrongSignupPass123!',
        }

        def register():
            close_old_connections()
            try:
                return APIClient().post(
                    '/api/auth/register/', payload, format='json',
                ).status_code
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = sorted(pool.map(lambda _: register(), range(2)))

        self.assertEqual(statuses, [201, 400])
        user = User.objects.get(username='billing_signup_race')
        self.assertEqual(BillingAccount.objects.filter(user=user).count(), 1)
        self.assertEqual(FreeTierGrant.objects.filter(account__user=user).count(), 1)

    def test_concurrent_provisioning_converges_on_one_account_and_grant(self):
        user = User.objects.create_user(
            username='billing-race', email='billing-race@example.com', password='TestPass123!',
        )

        def provision():
            close_old_connections()
            try:
                account, grant = ensure_free_v1_for_user(user)
                return str(account.account_id), grant.pk
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: provision(), range(2)))

        self.assertEqual(results[0], results[1])
        self.assertEqual(BillingAccount.objects.filter(user=user).count(), 1)
        self.assertEqual(FreeTierGrant.objects.filter(account__user=user).count(), 1)
