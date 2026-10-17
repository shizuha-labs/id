"""ID-39: transactional lifecycle outbox events."""
from unittest import mock
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from identity import lifecycle
from identity.lifecycle import LifecycleState, transition_user
from identity.models import UserLifecycleEvent, UserLifecycleEventDelivery, UserProfile

User = get_user_model()


class UserLifecycleOutboxTests(TestCase):
    def _user(self, username='outbox-user', *, keep_activation=False, account_type='human'):
        user = User.objects.create_user(
            username=username,
            email=f'{username}@example.com',
            password='not-used',
            is_active=True,
        )
        profile = user.profile
        profile.account_type = account_type
        profile.approval_status = 'approved'
        profile.lifecycle_state = LifecycleState.ACTIVE
        profile.save(update_fields=['account_type', 'approval_status', 'lifecycle_state'])
        if not keep_activation:
            UserLifecycleEvent.objects.filter(user_id=user.id).delete()
        return user

    def test_crossing_into_active_enqueues_mail_activation_transactionally(self):
        user = self._user('activated-user', keep_activation=True)
        event = UserLifecycleEvent.objects.get(user_id=user.id)
        self.assertEqual(event.event_type, UserLifecycleEvent.EVENT_ACTIVATED)
        self.assertEqual(event.payload['mailbox_email'], 'activated-user@shizuha.com')
        self.assertEqual(event.payload['account_type'], 'human')
        self.assertEqual(
            list(event.deliveries.values_list('consumer', flat=True)),
            [UserLifecycleEventDelivery.CONSUMER_MAIL],
        )

    def test_email_shaped_username_uses_external_localpart(self):
        user = self._user('legacy@example.com', keep_activation=True)
        event = UserLifecycleEvent.objects.get(user_id=user.id)
        self.assertEqual(event.payload['mailbox_email'], 'legacy@shizuha.com')

    def test_agent_activation_uses_profile_account_type(self):
        user = self._user('activated-agent', keep_activation=True, account_type='agent')
        event = UserLifecycleEvent.objects.get(user_id=user.id)
        self.assertEqual(event.payload['account_type'], 'agent')

    @mock.patch('identity.management.commands.dispatch_user_lifecycle_events.requests.post')
    def test_signed_mail_delivery_includes_authoritative_agent_type(self, post):
        response = mock.Mock()
        response.raise_for_status.return_value = None
        post.return_value = response
        self._user('signed-agent', keep_activation=True, account_type='agent')

        call_command(
            'dispatch_user_lifecycle_events',
            mail_url='http://mail.internal/api/internal/user-lifecycle-events/',
            mail_secret='mail-secret',
            consumers='mail',
        )

        import json
        payload = json.loads(post.call_args.kwargs['data'].decode('utf-8'))
        self.assertEqual(payload['account_type'], 'agent')
        self.assertIn('X-Shizuha-Signature', post.call_args.kwargs['headers'])

    def test_reconcile_replays_published_activation_missing_account_type_once(self):
        user = self._user('published-agent', keep_activation=True, account_type='agent')
        original = UserLifecycleEvent.objects.get(user_id=user.id)
        payload = dict(original.payload)
        payload.pop('account_type')
        original.payload = payload
        original.status = UserLifecycleEvent.STATUS_PUBLISHED
        original.save(update_fields=['payload', 'status'])
        delivery = original.deliveries.get(
            consumer=UserLifecycleEventDelivery.CONSUMER_MAIL,
        )
        delivery.status = UserLifecycleEvent.STATUS_PUBLISHED
        delivery.save(update_fields=['status'])

        call_command('reconcile_active_mailboxes')
        events = list(
            UserLifecycleEvent.objects.filter(user_id=user.id).order_by('created_at')
        )
        self.assertEqual(len(events), 2)
        self.assertEqual(events[-1].payload['account_type'], 'agent')

        call_command('reconcile_active_mailboxes')
        self.assertEqual(UserLifecycleEvent.objects.filter(user_id=user.id).count(), 2)

    def test_reconcile_repairs_unpublished_activation_in_place(self):
        user = self._user('pending-agent', keep_activation=True, account_type='agent')
        event = UserLifecycleEvent.objects.get(user_id=user.id)
        payload = dict(event.payload)
        payload.pop('account_type')
        event.payload = payload
        event.save(update_fields=['payload'])

        call_command('reconcile_active_mailboxes')

        self.assertEqual(UserLifecycleEvent.objects.filter(user_id=user.id).count(), 1)
        event.refresh_from_db()
        self.assertEqual(event.payload['account_type'], 'agent')

    def test_deactivate_delete_reactivate_edges_enqueue_events(self):
        user = self._user()

        transition_user(user, LifecycleState.DEACTIVATED, reason='suspend')
        event = UserLifecycleEvent.objects.get()
        self.assertEqual(event.event_type, UserLifecycleEvent.EVENT_DEACTIVATED)
        self.assertEqual(event.user_id, user.id)
        self.assertEqual(event.payload['to_state'], LifecycleState.DEACTIVATED)

        transition_user(user, LifecycleState.ACTIVE, reason='restore')
        transition_user(user, LifecycleState.DELETED, reason='delete')

        self.assertEqual(
            list(UserLifecycleEvent.objects.order_by('created_at').values_list('event_type', flat=True)),
            [
                UserLifecycleEvent.EVENT_DEACTIVATED,
                UserLifecycleEvent.EVENT_ACTIVATED,
                UserLifecycleEvent.EVENT_REACTIVATED,
                UserLifecycleEvent.EVENT_DELETED,
            ],
        )

    def test_enqueue_failure_aborts_lifecycle_transition(self):
        user = self._user('rollback-user')

        with mock.patch.object(lifecycle, '_enqueue_lifecycle_event', side_effect=RuntimeError('outbox down')):
            with self.assertRaises(RuntimeError):
                transition_user(user, LifecycleState.DEACTIVATED, reason='must rollback')

        user.refresh_from_db()
        profile = UserProfile.objects.get(user=user)
        self.assertTrue(user.is_active)
        self.assertEqual(profile.lifecycle_state, LifecycleState.ACTIVE)
        self.assertFalse(UserLifecycleEvent.objects.filter(user_id=user.id).exists())

    @mock.patch('identity.management.commands.dispatch_user_lifecycle_events.requests.post')
    def test_dispatcher_marks_event_published_and_sends_event_id(self, post):
        response = mock.Mock()
        response.raise_for_status.return_value = None
        post.return_value = response
        user = self._user('dispatch-user')
        transition_user(user, LifecycleState.DEACTIVATED, reason='dispatch')
        event = UserLifecycleEvent.objects.get()

        call_command(
            'dispatch_user_lifecycle_events',
            pulse_url='http://pulse.internal/api/internal/user-lifecycle-events/',
            pulse_secret='test-secret',
            consumers='pulse',
        )

        post.assert_called_once()
        self.assertEqual(post.call_args.kwargs['headers']['X-Shizuha-Service'], 'shizuha-id')
        self.assertIn('X-Shizuha-Signature', post.call_args.kwargs['headers'])
        self.assertNotIn('json', post.call_args.kwargs)
        import json
        payload = json.loads(post.call_args.kwargs['data'].decode('utf-8'))
        self.assertEqual(payload['event_id'], str(event.id))
        self.assertEqual(payload['event_type'], UserLifecycleEvent.EVENT_DEACTIVATED)
        delivery = event.deliveries.get(consumer=UserLifecycleEventDelivery.CONSUMER_PULSE)
        self.assertEqual(delivery.status, UserLifecycleEvent.STATUS_PUBLISHED)
        self.assertIsNotNone(delivery.published_at)
        event.refresh_from_db()
        self.assertEqual(event.status, UserLifecycleEvent.STATUS_PENDING)

    @override_settings(USER_LIFECYCLE_OUTBOX_MAX_LAG_SECONDS=300)
    def test_outbox_health_and_metrics_expose_fail_loud_alert_inputs(self):
        now = timezone.now()
        event = UserLifecycleEvent.objects.create(
            event_type=UserLifecycleEvent.EVENT_DEACTIVATED,
            user_id=4242,
            user_email='stuck@example.com',
            from_state=LifecycleState.ACTIVE,
            to_state=LifecycleState.DEACTIVATED,
            status=UserLifecycleEvent.STATUS_FAILED,
            next_attempt_at=now - timedelta(minutes=1),
            last_error='pulse unavailable',
        )
        UserLifecycleEvent.objects.filter(pk=event.pk).update(created_at=now - timedelta(minutes=10))

        health = self.client.get(reverse('user-lifecycle-outbox-health'))
        self.assertEqual(health.status_code, 503)
        self.assertEqual(health.json()['status'], 'degraded')
        self.assertEqual(health.json()['owner_route'], 'DevOps monitoring alert for user-lifecycle-outbox health')
        self.assertEqual(health.json()['failed_total'], 1)
        self.assertGreaterEqual(health.json()['oldest_lag_seconds'], 300)

        metrics = self.client.get(reverse('user-lifecycle-outbox-metrics'))
        self.assertEqual(metrics.status_code, 200)
        text = metrics.content.decode('utf-8')
        self.assertIn('shizuha_id_user_lifecycle_outbox_healthy 0', text)
        self.assertIn('shizuha_id_user_lifecycle_outbox_pending_total 1', text)
        self.assertIn('shizuha_id_user_lifecycle_outbox_failed_total 1', text)
        self.assertIn('shizuha_id_user_lifecycle_outbox_max_lag_seconds 300', text)
