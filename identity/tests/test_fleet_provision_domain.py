from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIRequestFactory

from identity.internal_urls import InternalFleetProvisionAgentView

User = get_user_model()

TOKEN = 'test-fleet-provisioner-token'


@override_settings(FLEET_PROVISIONER_TOKEN=TOKEN)
class FleetProvisionDomainTests(TestCase):
    """SCLI-205 → PLAT-4220: the scoped fleet provisioner CREATES and reconnects
    agent accounts on the canonical @shizuha.com domain (we don't own shizuha.io),
    while NEVER creating or hijacking a human account. The human-safety boundary
    is domain-independent: account_type='agent' is force-set, an existing human
    username is refused (username_taken_by_human), and a taken email is refused."""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.view = InternalFleetProvisionAgentView.as_view()
        # An existing agent account on the live @shizuha.com domain.
        self.agent = User.objects.create_user(username='akira', email='akira@shizuha.com')
        self.agent.profile.account_type = 'agent'
        self.agent.profile.save(update_fields=['account_type', 'updated_at'])
        # A human account on @shizuha.com — must never be touched.
        self.human = User.objects.create_user(username='hritik', email='test-owner@shizuha.com')

    def _post(self, payload, token=TOKEN):
        req = self.factory.post(
            '/api/internal/fleet/provision-agent/', payload, format='json',
            HTTP_X_FLEET_PROVISIONER_TOKEN=token,
        )
        return self.view(req)

    def test_reconnect_existing_agent_on_shizuha_com_is_allowed(self):
        resp = self._post({'username': 'akira', 'email': 'akira@shizuha.com', 'password': 'pw-at-least-8'})
        self.assertEqual(resp.status_code, 200, resp.data)
        self.assertEqual(resp.data['action'], 'reconnected')
        self.agent.refresh_from_db()
        self.assertTrue(self.agent.check_password('pw-at-least-8'))

    def test_reconnect_existing_agent_on_agents_domain_still_works(self):
        u = User.objects.create_user(username='banto', email='banto@agents.shizuha.io')
        u.profile.account_type = 'agent'
        u.profile.save(update_fields=['account_type', 'updated_at'])
        resp = self._post({'username': 'banto', 'email': 'banto@agents.shizuha.io', 'password': 'pw-at-least-8'})
        self.assertEqual(resp.status_code, 200, resp.data)
        self.assertEqual(resp.data['action'], 'reconnected')

    def test_create_new_shizuha_com_agent_is_ALLOWED(self):
        # PLAT-4220: a brand-new agent IS creatable on the canonical @shizuha.com
        # domain, and is marked account_type=agent.
        resp = self._post({'username': 'newbot', 'email': 'newbot@shizuha.com', 'password': 'pw-at-least-8'})
        self.assertEqual(resp.status_code, 201, resp.data)
        self.assertEqual(resp.data['action'], 'created')
        u = User.objects.get(username='newbot')
        self.assertEqual(u.email, 'newbot@shizuha.com')
        self.assertEqual(u.profile.account_type, 'agent')

    def test_create_new_agents_domain_account_still_allowed(self):
        resp = self._post({'username': 'newagent', 'email': 'newagent@agents.shizuha.io', 'password': 'pw-at-least-8'})
        self.assertEqual(resp.status_code, 201, resp.data)
        self.assertEqual(resp.data['action'], 'created')

    def test_personal_default_is_owner_bound_and_system_locked(self):
        owner = User.objects.create_user(username='alice', email='alice@example.com')
        payload = {
            'username': f'shizuha-{owner.id}',
            'email': f'shizuha-{owner.id}@agents.shizuha.io',
            'password': 'pw-at-least-8',
            'display_name': 'Shizuha',
            'owner_user_id': owner.id,
        }
        created = self._post(payload)
        self.assertEqual(created.status_code, 201, created.data)
        agent = User.objects.get(username=payload['username'])
        self.assertEqual(agent.profile.created_by_id, owner.id)
        self.assertEqual(agent.profile.ownership_class, 'personal_default_member')
        self.assertEqual(created.data['user_id'], agent.id)
        self.assertEqual(created.data['profile_id'], agent.profile.id)
        self.assertEqual(created.data['owner_user_id'], owner.id)
        self.assertEqual(created.data['owner_profile_id'], owner.profile.id)

        reconnected = self._post(payload)
        self.assertEqual(reconnected.status_code, 200, reconnected.data)
        self.assertEqual(reconnected.data['profile_id'], agent.profile.id)
        self.assertEqual(reconnected.data['owner_profile_id'], owner.profile.id)
        missing_owner = self._post({k: v for k, v in payload.items() if k != 'owner_user_id'})
        self.assertEqual(missing_owner.status_code, 409, missing_owner.data)

        other = User.objects.create_user(username='other-owner', email='other@example.com')
        wrong = self._post({**payload, 'owner_user_id': other.id})
        self.assertEqual(wrong.status_code, 400, wrong.data)

    def test_personal_default_rejects_noncanonical_identity(self):
        owner = User.objects.create_user(username='bob', email='bob@example.com')
        resp = self._post({
            'username': 'attacker-chosen',
            'email': 'attacker-chosen@agents.shizuha.io',
            'password': 'pw-at-least-8',
            'owner_user_id': owner.id,
        })
        self.assertEqual(resp.status_code, 400, resp.data)
        self.assertFalse(User.objects.filter(username='attacker-chosen').exists())

    def test_human_username_on_shizuha_com_is_refused(self):
        # SECURITY BOUNDARY: the domain gate now passes for @shizuha.com, but the
        # human-username check refuses it (409) before any write — the human is
        # never created/overwritten. This is the boundary that replaces the domain.
        resp = self._post({'username': 'hritik', 'email': 'test-owner@shizuha.com', 'password': 'pw-at-least-8'})
        self.assertEqual(resp.status_code, 409, resp.data)
        self.assertEqual(resp.data.get('reason'), 'username_taken_by_human')
        self.human.refresh_from_db()
        self.assertFalse(self.human.check_password('pw-at-least-8'))

    def test_taken_email_is_refused(self):
        # A @shizuha.com email already owned by a human cannot be claimed for a
        # new agent username.
        resp = self._post({'username': 'freshname', 'email': 'test-owner@shizuha.com', 'password': 'pw-at-least-8'})
        self.assertEqual(resp.status_code, 409, resp.data)
        self.assertEqual(resp.data.get('reason'), 'email_taken')
        self.assertFalse(User.objects.filter(username='freshname').exists())

    def test_non_agent_domain_is_rejected(self):
        resp = self._post({'username': 'x', 'email': 'x@evil.example.com', 'password': 'pw-at-least-8'})
        self.assertEqual(resp.status_code, 403, resp.data)

    def test_bad_token_is_forbidden(self):
        resp = self._post(
            {'username': 'akira', 'email': 'akira@shizuha.com', 'password': 'pw-at-least-8'},
            token='wrong-token',
        )
        self.assertEqual(resp.status_code, 403, resp.data)
