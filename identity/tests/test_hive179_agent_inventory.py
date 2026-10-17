"""HIVE-179: internal token-gated agent-inventory endpoint.

GET /api/internal/agents/            -> all account_type=agent accounts + owner
GET /api/internal/agents/?owner_id=  -> filtered to one owner
GET /api/internal/agents/?username=  -> unchanged single-agent lookup (back-compat)
"""
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase

from identity.models import UserProfile

User = get_user_model()

URL = '/api/internal/agents/'


class AgentInventoryTests(APITestCase):
    def setUp(self):
        self.owner = User.objects.create_user(username='hritik', email='h@x.com', password='x')
        self.other = User.objects.create_user(username='aoi-owner', email='a@x.com', password='x')
        self._agent('kai', self.owner, 'rt-1')
        self._agent('ren', self.owner, 'rt-2')
        self._agent('zen', self.other, 'rt-3')
        # a human account must NOT appear in the inventory
        User.objects.create_user(username='human-bob', email='b@x.com', password='x')
        # A non-human protocol canary is not a fleet runtime and must not be
        # handed to Hive for provisioning merely because it uses agent auth.
        canary = User.objects.create_user(
            username='mail-oauth-lifecycle-canary',
            email='mail-oauth-lifecycle-canary@agents.shizuha.io',
        )
        canary.profile.account_type = 'agent'
        canary.profile.ownership_class = 'system_canary'
        canary.profile.save(update_fields=['account_type', 'ownership_class'])

    def _agent(self, username, owner, rt):
        u = User.objects.create_user(
            username=username, email=f'{username}@shizuha.com', password='x')
        p = UserProfile.objects.get(user=u)  # auto-created by the post_save signal
        p.account_type = 'agent'
        p.created_by = owner
        p.agent_runtime_id = rt
        p.save()
        return u

    def test_inventory_lists_only_agents_with_owner(self):
        resp = self.client.get(URL)
        self.assertEqual(resp.status_code, 200, resp.content)
        usernames = {a['username'] for a in resp.data['agents']}
        self.assertEqual(usernames, {'kai', 'ren', 'zen'})  # human-bob excluded
        kai = next(a for a in resp.data['agents'] if a['username'] == 'kai')
        self.assertEqual(kai['created_by_id'], self.owner.id)
        self.assertEqual(kai['created_by_username'], 'hritik')
        self.assertEqual(kai['account_type'], 'agent')
        self.assertEqual(kai['agent_runtime_id'], 'rt-1')
        self.assertFalse(kai['is_staff'])
        self.assertFalse(kai['is_superuser'])
        self.assertIn('created_at', kai)
        self.assertEqual(resp.data['count'], 3)

    def test_filter_by_owner_id(self):
        resp = self.client.get(URL, {'owner_id': self.owner.id})
        self.assertEqual(resp.status_code, 200, resp.content)
        usernames = {a['username'] for a in resp.data['agents']}
        self.assertEqual(usernames, {'kai', 'ren'})  # zen belongs to the other owner

    def test_username_param_still_does_single_lookup(self):
        resp = self.client.get(URL, {'username': 'kai'})
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertTrue(resp.data['exists'])
        self.assertEqual(resp.data['account_type'], 'agent')
        self.assertNotIn('agents', resp.data)  # single-lookup shape, not the list
