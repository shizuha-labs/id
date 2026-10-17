from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIRequestFactory, force_authenticate

from identity.internal_urls import InternalUserListView
from identity.models import UserProfile

User = get_user_model()

BASE_ORG_MAP = {
    101: {'1': 'member'},
    202: {'1': 'member'},
    303: {'67': 'member'},
    404: {},
}
ORG_MAP = dict(BASE_ORG_MAP)


def _orgs(user):
    return ORG_MAP.get(user.id, {})


def _approve(user, *, account_type='human', lifecycle_state='active'):
    user.is_active = lifecycle_state == 'active'
    user.save(update_fields=['is_active'])
    profile, _ = UserProfile.objects.get_or_create(user=user)
    profile.approval_status = 'approved'
    profile.lifecycle_state = lifecycle_state
    profile.account_type = account_type
    profile.save(update_fields=['approval_status', 'lifecycle_state', 'account_type'])
    return user


class DirectoryScopeTests(TestCase):
    def setUp(self):
        ORG_MAP.clear()
        ORG_MAP.update(BASE_ORG_MAP)
        self.factory = APIRequestFactory()
        self.view = InternalUserListView.as_view()
        self.caller = _approve(User.objects.create_user(id=101, username='caller', email='caller@example.com'))
        self.same_org = _approve(User.objects.create_user(id=202, username='sameorg', email='same@example.com'))
        self.cross_org = _approve(User.objects.create_user(id=303, username='external', email='external@example.com'))
        self.no_org = _approve(User.objects.create_user(id=404, username='noorg', email='noorg@example.com'))
        self.deleted = _approve(
            User.objects.create_user(id=505, username='deleted', email='deleted@example.com'),
            lifecycle_state='deleted',
        )
        self.agent = _approve(
            User.objects.create_user(id=606, username='agent', email='agent@agents.shizuha.io'),
            account_type='agent',
        )

    def _get(self, caller, params=None):
        request = self.factory.get('/internal/users/', params or {})
        force_authenticate(request, user=caller)
        with patch('identity.internal_urls._fetch_org_memberships', side_effect=_orgs):
            return self.view(request)

    def test_same_org_visible_cross_org_hidden_and_count_scoped(self):
        response = self._get(self.caller, {'limit': 100})

        self.assertEqual(response.status_code, 200)
        usernames = [row['username'] for row in response.data['results']]
        self.assertEqual(response.data['count'], 2)
        self.assertEqual(usernames, ['caller', 'sameorg'])
        self.assertNotIn('external', usernames)
        self.assertNotIn('deleted', usernames)

    def test_search_is_scoped_before_count_and_pagination(self):
        response = self._get(self.caller, {'search': 'external', 'limit': 1})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['count'], 0)
        self.assertEqual(response.data['results'], [])

        page_one = self._get(self.caller, {'limit': 1, 'offset': 0})
        page_two = self._get(self.caller, {'limit': 1, 'offset': 1})
        self.assertEqual([u['username'] for u in page_one.data['results']], ['caller'])
        self.assertEqual([u['username'] for u in page_two.data['results']], ['sameorg'])

    def test_self_lookup_allowed_without_org_membership(self):
        response = self._get(self.no_org, {'ids': str(self.no_org.id)})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['results'][0]['username'], 'noorg')

    def test_agent_service_account_uses_same_org_policy(self):
        with patch.dict(ORG_MAP, {self.agent.id: {'1': 'member'}}):
            response = self._get(self.agent, {'limit': 100})

        usernames = [row['username'] for row in response.data['results']]
        self.assertEqual(response.status_code, 200)
        self.assertIn('caller', usernames)
        self.assertIn('sameorg', usernames)
        self.assertIn('agent', usernames)
        self.assertNotIn('external', usernames)

    def test_staff_can_list_active_directory(self):
        staff = _approve(User.objects.create_user(id=707, username='staff', email='staff@example.com'))
        staff.is_staff = True
        staff.save(update_fields=['is_staff'])
        response = self._get(staff, {'limit': 100})

        usernames = [row['username'] for row in response.data['results']]
        self.assertEqual(response.status_code, 200)
        self.assertIn('external', usernames)
        self.assertNotIn('deleted', usernames)

    def test_anonymous_cannot_enumerate(self):
        request = self.factory.get('/internal/users/')
        response = self.view(request)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data['error'], 'Authentication required')
