"""ID-37 (HLD ID-5 §4.5): admin-audit query API, verifier, and redaction.

Proves: (1) the ledger read endpoints are staff/superuser only; (2) list
filters by actor, target user, action, service slug, outcome, and date range
are correct; (3) before/after payloads are redacted so no secret material
leaves the query surface; (4) the hash-chain verifier (API + management
command) detects a tampered event and reports the first broken seq.
"""
from datetime import timedelta
from io import StringIO

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from identity.admin_audit import (
    ACTION_ADMIN_SET_PASSWORD,
    ACTION_SERVICE_CATALOG_UPDATE,
    ACTION_USER_SERVICES_GRANT,
    ACTION_USER_SERVICES_REVOKE,
    audited_admin_set_password,
    audited_service_catalog_update,
    audited_user_services_change,
    redact_audit_payload,
    verify_chain,
)
from identity.models import AdminAuditEvent, Tool, UserProfile

User = get_user_model()


class AdminAuditQueryBase(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user(
            username='staff', password='pw', email='staff@shizuha.com',
            is_staff=True,
        )
        self.superuser = User.objects.create_user(
            username='root', password='pw', email='root@shizuha.com',
            is_staff=False, is_superuser=True,
        )
        self.regular = User.objects.create_user(
            username='bob', password='pw', email='bob@shizuha.com',
        )
        self.target = User.objects.create_user(
            username='alice', password='old-password-1', email='alice@shizuha.com',
        )
        for user in (self.staff, self.superuser, self.regular, self.target):
            UserProfile.objects.update_or_create(
                user=user,
                defaults={'approval_status': 'approved', 'lifecycle_state': 'active'},
            )
        self.tool = Tool.objects.create(
            slug='ledgertool', display_name='Ledger Tool', requires_approval=True,
            is_default_enabled=False,
        )
        self.client = APIClient()

    def _seed_events(self):
        """Three events by two actors on distinct targets/actions."""
        audited_service_catalog_update(
            actor=self.staff, tool=self.tool, changes={'is_active': False},
        )  # seq 1: staff -> tool catalog update
        audited_user_services_change(
            actor=self.staff, user=self.target, tools=[self.tool], action='grant',
        )  # seq 2: staff -> user grant
        audited_user_services_change(
            actor=self.superuser, user=self.target, tools=[self.tool], action='revoke',
        )  # seq 3: superuser -> user revoke


class AuthzTests(AdminAuditQueryBase):
    def test_regular_user_forbidden_on_all_read_endpoints(self):
        self.client.force_authenticate(self.regular)
        for name in ('admin-audit-events', 'admin-audit-verify'):
            resp = self.client.get(reverse(name))
            self.assertEqual(resp.status_code, 403, name)

    def test_anonymous_forbidden(self):
        resp = self.client.get(reverse('admin-audit-events'))
        self.assertIn(resp.status_code, (401, 403))

    def test_staff_allowed(self):
        self.client.force_authenticate(self.staff)
        resp = self.client.get(reverse('admin-audit-events'))
        self.assertEqual(resp.status_code, 200)

    def test_superuser_without_staff_allowed(self):
        self.client.force_authenticate(self.superuser)
        resp = self.client.get(reverse('admin-audit-events'))
        self.assertEqual(resp.status_code, 200)


class FilterTests(AdminAuditQueryBase):
    def setUp(self):
        super().setUp()
        self._seed_events()
        self.client.force_authenticate(self.staff)

    def _seqs(self, **params):
        resp = self.client.get(reverse('admin-audit-events'), params)
        self.assertEqual(resp.status_code, 200, resp.data)
        return {row['seq'] for row in resp.data['results']}

    def test_no_filter_returns_all_newest_first(self):
        resp = self.client.get(reverse('admin-audit-events'))
        self.assertEqual(resp.data['count'], 3)
        self.assertEqual([r['seq'] for r in resp.data['results']], [3, 2, 1])

    def test_filter_by_action(self):
        self.assertEqual(self._seqs(action=ACTION_USER_SERVICES_GRANT), {2})

    def test_filter_by_actor_id(self):
        self.assertEqual(self._seqs(actor_id=self.superuser.id), {3})

    def test_filter_by_actor_username(self):
        self.assertEqual(self._seqs(actor_username='staff'), {1, 2})

    def test_filter_by_target_user(self):
        # Catalog update (seq 1) targets the tool, not the user.
        self.assertEqual(self._seqs(target_user_id=self.target.id), {2, 3})

    def test_filter_by_service_slug(self):
        # slug appears as tool target (1) and in grant/revoke requested_slugs (2,3)
        self.assertEqual(self._seqs(service_slug='ledgertool'), {1, 2, 3})
        self.assertEqual(self._seqs(service_slug='nope'), set())

    def test_filter_by_outcome_allowed(self):
        self.assertEqual(self._seqs(outcome='allowed'), {1, 2, 3})

    def test_filter_by_outcome_denied_empty_when_none(self):
        self.assertEqual(self._seqs(outcome='denied'), set())

    def test_invalid_outcome_is_400(self):
        resp = self.client.get(reverse('admin-audit-events'), {'outcome': 'bogus'})
        self.assertEqual(resp.status_code, 400)

    def test_filter_by_date_range(self):
        # Compute boundaries in the configured timezone (Asia/Kolkata) so the
        # bare-date semantics (start/end of the local day) align with the
        # events' local dates regardless of when the suite runs. UTC-based
        # dates made this test time-of-day dependent: after 18:30Z (00:00 IST)
        # events land on the UTC-tomorrow date, breaking both assertions.
        local_now = timezone.localtime(timezone.now())
        future = (local_now + timedelta(days=1)).date().isoformat()
        past = (local_now - timedelta(days=1)).date().isoformat()
        self.assertEqual(self._seqs(**{'from': past, 'to': future}), {1, 2, 3})
        # A window entirely in the future excludes everything.
        self.assertEqual(self._seqs(**{'from': future}), set())

    def test_invalid_date_is_400(self):
        resp = self.client.get(reverse('admin-audit-events'), {'from': 'not-a-date'})
        self.assertEqual(resp.status_code, 400)

    def test_pagination(self):
        resp = self.client.get(reverse('admin-audit-events'), {'limit': 2, 'offset': 0})
        self.assertEqual(resp.data['count'], 3)
        self.assertEqual(len(resp.data['results']), 2)
        self.assertEqual([r['seq'] for r in resp.data['results']], [3, 2])
        resp2 = self.client.get(reverse('admin-audit-events'), {'limit': 2, 'offset': 2})
        self.assertEqual([r['seq'] for r in resp2.data['results']], [1])


class RedactionTests(AdminAuditQueryBase):
    def test_redact_helper_scrubs_string_secrets_keeps_safe_flags(self):
        payload = {
            'password': 'hunter2',
            'password_changed': True,
            'api_key': 'sk-live-123',
            'break_glass_reason': 'incident-42',
            'nested': {'token': 'abc', 'count': 3},
            'slugs': ['a', 'b'],
        }
        out = redact_audit_payload(payload)
        self.assertEqual(out['password'], '[redacted]')
        self.assertEqual(out['api_key'], '[redacted]')
        self.assertEqual(out['nested']['token'], '[redacted]')
        # Safe non-secret values survive.
        self.assertTrue(out['password_changed'])
        self.assertEqual(out['break_glass_reason'], 'incident-42')
        self.assertEqual(out['nested']['count'], 3)
        self.assertEqual(out['slugs'], ['a', 'b'])

    def test_detail_endpoint_redacts_secret_values(self):
        # Append a hostile event carrying a raw secret to prove the query
        # surface scrubs it even if a future writer stored one.
        AdminAuditEvent.objects.append(
            action='test.leak', actor=self.staff, target_type='user',
            target_id=self.target.id, target_repr='alice',
            after={'password': 'hunter2', 'password_changed': True},
        )
        self.client.force_authenticate(self.staff)
        seq = AdminAuditEvent.objects.get(action='test.leak').seq
        resp = self.client.get(reverse('admin-audit-event-detail', args=[seq]))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data['after']['password'], '[redacted]')
        self.assertTrue(resp.data['after']['password_changed'])

    def test_set_password_event_never_exposes_material(self):
        audited_admin_set_password(
            actor=self.superuser, user=self.target, new_password='brand-new-pass-9',
        )
        self.client.force_authenticate(self.staff)
        resp = self.client.get(reverse('admin-audit-events'),
                               {'action': ACTION_ADMIN_SET_PASSWORD})
        seq = resp.data['results'][0]['seq']
        detail = self.client.get(reverse('admin-audit-event-detail', args=[seq]))
        self.assertNotIn('brand-new-pass-9', str(detail.data))
        self.assertTrue(detail.data['after']['password_changed'])


class VerifierTests(AdminAuditQueryBase):
    def setUp(self):
        super().setUp()
        self._seed_events()

    def test_verify_endpoint_reports_intact_chain(self):
        self.client.force_authenticate(self.superuser)
        resp = self.client.get(reverse('admin-audit-verify'))
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.data['ok'])
        self.assertEqual(resp.data['checked'], 3)
        self.assertIsNone(resp.data['first_bad_seq'])

    def test_detail_reports_per_event_chain_status(self):
        self.client.force_authenticate(self.staff)
        resp = self.client.get(reverse('admin-audit-event-detail', args=[2]))
        self.assertTrue(resp.data['chain_status']['intact'])
        self.assertTrue(resp.data['chain_status']['event_hash_valid'])
        self.assertTrue(resp.data['chain_status']['prev_hash_valid'])

    def _tamper_seq2(self):
        # In-place edit that bypasses the append-only ORM guard (raw UPDATE),
        # exactly the tamper the hash chain exists to catch.
        AdminAuditEvent.objects.filter(seq=2).update(after={'enabled_services': ['HACKED']})

    def test_verify_endpoint_detects_tamper(self):
        self._tamper_seq2()
        self.client.force_authenticate(self.staff)
        resp = self.client.get(reverse('admin-audit-verify'))
        self.assertFalse(resp.data['ok'])
        self.assertEqual(resp.data['first_bad_seq'], 2)
        self.assertEqual(resp.data['checked'], 1)  # seq 1 verified before the break

    def test_verify_chain_helper_detects_tamper(self):
        self._tamper_seq2()
        result = verify_chain()
        self.assertFalse(result.ok)
        self.assertEqual(result.first_bad_seq, 2)

    def test_management_command_ok(self):
        out = StringIO()
        call_command('verify_admin_audit_chain', stdout=out)
        text = out.getvalue()
        self.assertIn('admin-audit chain: OK', text)
        self.assertIn('events checked: 3', text)

    def test_management_command_json_and_broken_exit(self):
        self._tamper_seq2()
        out = StringIO()
        with self.assertRaises(SystemExit) as ctx:
            call_command('verify_admin_audit_chain', '--json', stdout=out)
        self.assertEqual(ctx.exception.code, 1)
        import json
        payload = json.loads(out.getvalue())
        self.assertFalse(payload['ok'])
        self.assertEqual(payload['first_bad_seq'], 2)
        self.assertIn(ACTION_USER_SERVICES_GRANT, payload['action_counts'])
