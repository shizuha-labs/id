from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIRequestFactory

from identity.internal_urls import InternalAgentClaimView, InternalAgentIdentityView

User = get_user_model()


class InternalAgentClaimTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.view = InternalAgentIdentityView.as_view()
        self.legacy_claim_view = InternalAgentClaimView.as_view()
        self.owner = User.objects.create_user(username='owner', email='owner@example.com')
        self.other = User.objects.create_user(username='other', email='other@example.com')
        self.agent = User.objects.create_user(username='scout', email='scout@agents.shizuha.io')
        self.agent.profile.account_type = 'agent'
        self.agent.profile.created_by = None
        self.agent.profile.save(update_fields=['account_type', 'created_by', 'updated_at'])

    def _patch(self, payload):
        return self.view(self.factory.patch('/api/internal/agents/', payload, format='json'))

    def _legacy_claim(self, payload):
        return self.legacy_claim_view(
            self.factory.post('/api/internal/agents/claim/', payload, format='json')
        )

    def _legacy_reconnect(self, payload):
        return self.view(
            self.factory.post('/api/internal/agents/', payload, format='json')
        )

    def test_nonstaff_claims_orphan_agent_idempotently(self):
        resp = self._patch({'agent_user_id': self.agent.id, 'actor_user_id': self.owner.id})
        self.assertEqual(resp.status_code, 200, resp.data)
        self.assertEqual(resp.data['action'], 'claimed')
        self.agent.profile.refresh_from_db()
        self.assertEqual(self.agent.profile.created_by_id, self.owner.id)

        again = self._patch({'agent_user_id': self.agent.id, 'actor_user_id': self.owner.id})
        self.assertEqual(again.status_code, 200, again.data)
        self.assertEqual(again.data['action'], 'already_owned')

    def test_nonstaff_cannot_steal_owned_agent(self):
        self.agent.profile.created_by = self.owner
        self.agent.profile.save(update_fields=['created_by', 'updated_at'])
        resp = self._patch({'agent_user_id': self.agent.id, 'actor_user_id': self.other.id})
        self.assertEqual(resp.status_code, 409, resp.data)
        self.agent.profile.refresh_from_db()
        self.assertEqual(self.agent.profile.created_by_id, self.owner.id)

    def test_staff_can_reassign_and_unclaim(self):
        self.other.is_staff = True
        self.other.save(update_fields=['is_staff'])
        self.agent.profile.created_by = self.owner
        self.agent.profile.save(update_fields=['created_by', 'updated_at'])
        resp = self._patch({'agent_user_id': self.agent.id, 'actor_user_id': self.other.id})
        self.assertEqual(resp.status_code, 200, resp.data)
        self.assertEqual(resp.data['action'], 'reassigned')
        self.agent.profile.refresh_from_db()
        self.assertEqual(self.agent.profile.created_by_id, self.other.id)

        clear = self._patch({'agent_user_id': self.agent.id, 'actor_user_id': self.other.id, 'action': 'unclaim'})
        self.assertEqual(clear.status_code, 200, clear.data)
        self.agent.profile.refresh_from_db()
        self.assertIsNone(self.agent.profile.created_by_id)

    def test_body_is_staff_true_does_not_authorize_nonstaff_reassign_or_unclaim(self):
        self.agent.profile.created_by = self.owner
        self.agent.profile.save(update_fields=['created_by', 'updated_at'])

        steal = self._patch({'agent_user_id': self.agent.id, 'actor_user_id': self.other.id, 'is_staff': True})
        self.assertEqual(steal.status_code, 409, steal.data)
        self.agent.profile.refresh_from_db()
        self.assertEqual(self.agent.profile.created_by_id, self.owner.id)

        clear = self._patch({'agent_user_id': self.agent.id, 'actor_user_id': self.other.id, 'is_staff': True, 'action': 'unclaim'})
        self.assertEqual(clear.status_code, 403, clear.data)
        self.agent.profile.refresh_from_db()
        self.assertEqual(self.agent.profile.created_by_id, self.owner.id)

    def test_human_target_rejected(self):
        resp = self._patch({'agent_user_id': self.owner.id, 'actor_user_id': self.other.id})
        self.assertEqual(resp.status_code, 400, resp.data)

    def test_personal_default_cannot_be_reassigned_or_unclaimed_even_by_staff(self):
        self.other.is_staff = True
        self.other.save(update_fields=['is_staff'])
        self.agent.profile.created_by = self.owner
        self.agent.profile.ownership_class = 'personal_default_member'
        self.agent.profile.save(update_fields=['created_by', 'ownership_class', 'updated_at'])

        for payload in (
            {'agent_user_id': self.agent.id, 'actor_user_id': self.other.id},
            {'agent_user_id': self.agent.id, 'actor_user_id': self.other.id, 'action': 'unclaim'},
        ):
            resp = self._patch(payload)
            self.assertEqual(resp.status_code, 409, resp.data)
            self.assertEqual(resp.data['reason'], 'system_locked_personal_default')
        self.agent.profile.refresh_from_db()
        self.assertEqual(self.agent.profile.created_by_id, self.owner.id)

    def test_personal_default_cannot_be_reassigned_through_legacy_claim_even_with_force(self):
        self.agent.profile.created_by = self.owner
        self.agent.profile.ownership_class = 'personal_default_member'
        self.agent.profile.save(update_fields=['created_by', 'ownership_class', 'updated_at'])

        for force in (False, True):
            with self.subTest(force=force):
                resp = self._legacy_claim({
                    'username': self.agent.username,
                    'owner_id': self.other.id,
                    'force': force,
                })
                self.assertEqual(resp.status_code, 409, resp.data)
                self.assertEqual(resp.data['reason'], 'system_locked_personal_default')
                self.agent.profile.refresh_from_db()
                self.assertEqual(self.agent.profile.created_by_id, self.owner.id)
                self.assertEqual(self.agent.profile.ownership_class, 'personal_default_member')

    def test_personal_default_cannot_be_mutated_through_legacy_reconnect(self):
        self.agent.profile.created_by = self.owner
        self.agent.profile.ownership_class = 'personal_default_member'
        self.agent.profile.agent_runtime_id = 'runtime-original'
        self.agent.profile.save(update_fields=[
            'created_by', 'ownership_class', 'agent_runtime_id', 'updated_at',
        ])
        original = {
            'username': self.agent.username,
            'email': self.agent.email,
            'created_by_id': self.agent.profile.created_by_id,
            'ownership_class': self.agent.profile.ownership_class,
            'agent_runtime_id': self.agent.profile.agent_runtime_id,
        }

        resp = self._legacy_reconnect({
            'username': self.agent.username,
            'email': 'rewritten@agents.shizuha.io',
            'created_by_id': self.owner.id,
            'runtime_id': 'runtime-rewritten',
        })

        self.assertEqual(resp.status_code, 409, resp.data)
        self.assertEqual(resp.data['reason'], 'system_locked_personal_default')
        self.agent.refresh_from_db()
        self.agent.profile.refresh_from_db()
        self.assertEqual(self.agent.username, original['username'])
        self.assertEqual(self.agent.email, original['email'])
        self.assertEqual(self.agent.profile.created_by_id, original['created_by_id'])
        self.assertEqual(self.agent.profile.ownership_class, original['ownership_class'])
        self.assertEqual(self.agent.profile.agent_runtime_id, original['agent_runtime_id'])
