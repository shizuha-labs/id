"""New humans get a hibernated personal Shizuha; activation itself never fails."""
from unittest import mock

import requests
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from identity.lifecycle import LifecycleState, enqueue_user_activated, transition_user

User = get_user_model()


def _human(username, *, staff=False, account_type='human', state=LifecycleState.PENDING):
    user = User.objects.create_user(
        username=username,
        email=f'{username}@gmail.com',
        password='Pass123!x',
        is_staff=staff,
        is_superuser=staff,
        is_active=False,
    )
    profile = user.profile
    profile.account_type = account_type
    profile.lifecycle_state = state
    profile.approval_status = 'pending' if state == LifecycleState.PENDING else 'approved'
    profile.save(update_fields=['account_type', 'lifecycle_state', 'approval_status'])
    return user


class PersonalAgentNotifyTests(TestCase):
    @override_settings(SHIZUHA_HIVE_INTERNAL_URL='http://hive.test')
    @mock.patch('identity.personal_agent_notify.requests.post')
    def test_human_activation_notifies_hive(self, post):
        post.return_value = mock.Mock(status_code=201)
        user = _human('newhuman')
        with self.captureOnCommitCallbacks(execute=True):
            transition_user(user, LifecycleState.ACTIVE, reason='approve')
        post.assert_called_once()
        kwargs = post.call_args.kwargs
        self.assertEqual(
            post.call_args.args[0],
            'http://hive.test/api/v1/fleet/internal/ensure-personal-agent/',
        )
        self.assertEqual(kwargs['json']['owner_id'], user.id)
        self.assertEqual(kwargs['json']['username'], 'newhuman')
        self.assertEqual(kwargs['json']['account_type'], 'human')
        self.assertFalse(kwargs['json']['is_staff'])

    @override_settings(SHIZUHA_HIVE_INTERNAL_URL='http://hive.test')
    @mock.patch('identity.personal_agent_notify.requests.post')
    def test_agent_activation_does_not_notify(self, post):
        user = _human('newagent', account_type='agent')
        with self.captureOnCommitCallbacks(execute=True):
            transition_user(user, LifecycleState.ACTIVE, reason='approve')
        post.assert_not_called()

    @override_settings(SHIZUHA_HIVE_INTERNAL_URL='http://hive.test')
    @mock.patch('identity.personal_agent_notify.requests.post')
    def test_staff_activation_does_not_notify(self, post):
        user = _human('hritikstaff', staff=True)
        with self.captureOnCommitCallbacks(execute=True):
            transition_user(user, LifecycleState.ACTIVE, reason='approve')
        post.assert_not_called()

    @override_settings(SHIZUHA_HIVE_INTERNAL_URL='http://hive.test')
    @mock.patch('identity.personal_agent_notify.requests.post',
                side_effect=requests.ConnectionError('hive down'))
    def test_notify_failure_does_not_break_activation(self, _post):
        user = _human('resilienthuman')
        with self.captureOnCommitCallbacks(execute=True):
            profile = transition_user(user, LifecycleState.ACTIVE, reason='approve')
        profile.refresh_from_db()
        self.assertEqual(profile.lifecycle_state, LifecycleState.ACTIVE)
        user.refresh_from_db()
        self.assertTrue(user.is_active)

    @override_settings(SHIZUHA_HIVE_INTERNAL_URL='')
    @mock.patch('identity.personal_agent_notify.requests.post')
    def test_empty_hive_url_skips_notify(self, post):
        user = _human('localhuman')
        with self.captureOnCommitCallbacks(execute=True):
            enqueue_user_activated(user=user, from_state=LifecycleState.PENDING)
        post.assert_not_called()


class InternalHumanDirectoryTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.human = _human('komaldir', state=LifecycleState.ACTIVE)
        self.human.is_active = True
        self.human.save(update_fields=['is_active'])
        self.agent = _human('kaidir', account_type='agent', state=LifecycleState.ACTIVE)
        self.agent.is_active = True
        self.agent.save(update_fields=['is_active'])
        self.staff = _human('admindir', staff=True, state=LifecycleState.ACTIVE)
        self.staff.is_active = True
        self.staff.save(update_fields=['is_active'])

    def test_lists_active_humans_including_staff_excluding_agents(self):
        resp = self.client.get('/api/internal/humans/?limit=200')
        self.assertEqual(resp.status_code, 200)
        rows = {row['username']: row for row in resp.data['results']}
        self.assertIn('komaldir', rows)
        self.assertIn('admindir', rows)
        self.assertTrue(rows['admindir']['is_staff'])
        self.assertNotIn('kaidir', rows)
        self.assertEqual(rows['komaldir']['account_type'], 'human')
