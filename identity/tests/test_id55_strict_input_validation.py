"""ID-55: deny-by-default input validation — StrictInputMixin regressions.

Proves that the id_* INPUT serializers reject unknown/unexpected request keys
with a validation error (HTTP 400 at the view layer) instead of DRF's default
of silently ignoring them, while well-formed input still validates. No DB/Redis
needed — these are pure serializer-level checks.
"""
import requests

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase, override_settings

from identity.permissions import IsStaffAdmin
from identity.views import AdminServiceListView

from identity.serializers import (
    AdminServiceUpdateSerializer,
    AdminUserServiceGrantSerializer,
    LoginSerializer,
    PasswordChangeSerializer,
    ServiceAccessRequestCreateSerializer,
    ServiceAccessRequestReviewSerializer,
    UserApprovalReviewSerializer,
    StrictInputMixin,
)


class StrictInputValidationTests(SimpleTestCase):
    def test_admin_service_update_rejects_unknown_field(self):
        s = AdminServiceUpdateSerializer(data={'is_active': True, 'bogus': 'x'})
        self.assertFalse(s.is_valid())
        self.assertIn('bogus', s.errors)

    def test_admin_service_update_accepts_known_fields(self):
        s = AdminServiceUpdateSerializer(data={'is_active': True, 'requires_approval': False})
        self.assertTrue(s.is_valid(), s.errors)

    def test_login_rejects_unknown_field(self):
        s = LoginSerializer(data={'username': 'alice', 'password': 'pw', 'evil': 1})
        self.assertFalse(s.is_valid())
        self.assertIn('evil', s.errors)

    def test_login_accepts_declared_fields(self):
        s = LoginSerializer(data={'username': 'alice', 'password': 'pw'})
        self.assertTrue(s.is_valid(), s.errors)

    def test_password_change_rejects_unknown_field(self):
        s = PasswordChangeSerializer(data={
            'old_password': 'a', 'new_password': 'b', 'new_password2': 'b', 'x': 'y',
        })
        self.assertFalse(s.is_valid())
        self.assertIn('x', s.errors)

    def test_review_rejects_unknown_field(self):
        s = ServiceAccessRequestReviewSerializer(data={'status': 'approved', 'sneaky': 1})
        self.assertFalse(s.is_valid())
        self.assertIn('sneaky', s.errors)

    def test_user_approval_rejects_unknown_field(self):
        s = UserApprovalReviewSerializer(data={'status': 'denied', 'note2': 'x'})
        self.assertFalse(s.is_valid())
        self.assertIn('note2', s.errors)

    def test_grant_rejects_unknown_field(self):
        s = AdminUserServiceGrantSerializer(data={
            'service_slugs': ['mail'], 'action': 'grant', 'nope': True,
        })
        self.assertFalse(s.is_valid())
        self.assertIn('nope', s.errors)

    def test_multi_alias_declared_fields_are_not_rejected(self):
        # ServiceAccessRequestCreate declares tool_slug/service/service_slug as
        # real fields (ID-42 alias) — deny-by-default must NOT reject them.
        s = ServiceAccessRequestCreateSerializer(data={'service': 'mail'})
        self.assertTrue(s.is_valid(), s.errors)

    def test_multiple_unknown_fields_all_reported(self):
        s = AdminServiceUpdateSerializer(data={'is_active': True, 'a': 1, 'b': 2})
        self.assertFalse(s.is_valid())
        self.assertIn('a', s.errors)
        self.assertIn('b', s.errors)

    def test_mixin_is_applied_to_input_serializers(self):
        for cls in (LoginSerializer, PasswordChangeSerializer,
                    AdminServiceUpdateSerializer, AdminUserServiceGrantSerializer,
                    ServiceAccessRequestCreateSerializer,
                    ServiceAccessRequestReviewSerializer, UserApprovalReviewSerializer):
            self.assertTrue(issubclass(cls, StrictInputMixin), cls.__name__)


class StaffBoundaryDenialEventTests(SimpleTestCase):
    @staticmethod
    def _denied_request():
        user = SimpleNamespace(
            id=42,
            username='ren',
            email='ren@shizuha.com',
            is_authenticated=True,
            is_staff=False,
            organization_memberships={1: 'member'},
        )
        request = SimpleNamespace(user=user, auth={}, headers={}, method='GET')
        return request, IsStaffAdmin().has_permission(request, AdminServiceListView())

    @patch('identity.permissions.emit_boundary_denial')
    def test_admin_service_denial_emits_only_for_designated_staff_view(self, emit):
        user = SimpleNamespace(
            id=42,
            username='ren',
            email='ren@shizuha.com',
            is_authenticated=True,
            is_staff=False,
        )
        request = SimpleNamespace(user=user, auth={}, headers={}, method='GET')

        allowed = IsStaffAdmin().has_permission(request, AdminServiceListView())

        self.assertFalse(allowed)
        emit.assert_called_once()
        self.assertEqual(emit.call_args.kwargs['service'], 'id')
        self.assertEqual(emit.call_args.kwargs['operation'], 'id.admin_list_services')
        self.assertEqual(emit.call_args.kwargs['reason'], 'staff_endpoint')

    @patch('identity.permissions.emit_boundary_denial')
    def test_unrelated_staff_permission_denial_is_negative_control(self, emit):
        user = SimpleNamespace(is_authenticated=True, is_staff=False)
        request = SimpleNamespace(user=user)

        allowed = IsStaffAdmin().has_permission(request, SimpleNamespace())

        self.assertFalse(allowed)
        emit.assert_not_called()

    @override_settings(CONNECT_SECURITY_EVENT_ORIGIN_SECRET='boundary-secret')
    @patch('identity.security_events.record_boundary_event_outcome')
    @patch('identity.security_events.requests.post')
    def test_boundary_producer_success_is_counted_without_changing_denial(self, post, record):
        post.return_value.status_code = 202

        _request, allowed = self._denied_request()

        self.assertFalse(allowed)
        record.assert_called_once_with('success')
        payload = post.call_args.kwargs['json']
        self.assertEqual(payload['data']['operation'], 'id.admin_list_services')
        self.assertNotIn('query', payload['data'])

    def test_boundary_producer_failures_are_counted_without_changing_denial(self):
        cases = (
            ('disabled', {'CONNECT_SECURITY_EVENT_EMIT_ENABLED': False}, None, None),
            ('missing_secret', {'CONNECT_SECURITY_EVENT_ORIGIN_SECRET': ''}, None, None),
            ('non_202', {'CONNECT_SECURITY_EVENT_ORIGIN_SECRET': 'boundary-secret'}, 503, None),
            ('timeout', {'CONNECT_SECURITY_EVENT_ORIGIN_SECRET': 'boundary-secret'}, None, requests.Timeout()),
            ('exception', {'CONNECT_SECURITY_EVENT_ORIGIN_SECRET': 'boundary-secret'}, None, RuntimeError('boom')),
        )
        for expected, setting_overrides, status_code, side_effect in cases:
            with self.subTest(expected=expected), override_settings(**setting_overrides), patch(
                'identity.security_events.record_boundary_event_outcome',
            ) as record, patch('identity.security_events.requests.post') as post:
                if status_code is not None:
                    post.return_value.status_code = status_code
                if side_effect is not None:
                    post.side_effect = side_effect

                _request, allowed = self._denied_request()

                self.assertFalse(allowed)
                record.assert_called_once_with(expected)

    @patch('identity.security_events._metrics_redis_client')
    def test_boundary_metrics_render_bounded_service_outcomes(self, client_factory):
        from identity.security_events import render_boundary_event_metrics

        client = MagicMock()
        client.mget.return_value = ['4'] + ['0'] * 7
        client_factory.return_value = client

        text = render_boundary_event_metrics()

        self.assertIn(
            'platform_boundary_event_producer_total{service="id",outcome="success"} 4',
            text,
        )
        self.assertIn(
            'platform_boundary_event_producer_probe_errors{service="id"} 0',
            text,
        )

    @patch('identity.security_events._metrics_redis_client')
    def test_boundary_metrics_omit_unavailable_counters_without_resetting_recovery(
        self, client_factory,
    ):
        """Mirror the production N -> Redis error -> same N scrape order."""
        from identity.security_events import render_boundary_event_metrics

        client = MagicMock()
        historical = ['6', '0', '1'] + ['0'] * 5
        client.mget.side_effect = [historical, ConnectionError('redis down'), historical]
        client_factory.return_value = client

        before = render_boundary_event_metrics()
        with self.assertLogs('identity.security_events', level='ERROR'):
            unavailable = render_boundary_event_metrics()
        recovered = render_boundary_event_metrics()

        before_counters = [
            line for line in before.splitlines()
            if line.startswith('platform_boundary_event_producer_total')
        ]
        recovered_counters = [
            line for line in recovered.splitlines()
            if line.startswith('platform_boundary_event_producer_total')
        ]
        self.assertEqual(recovered_counters, before_counters)
        self.assertIn(
            'platform_boundary_event_producer_total'
            '{service="id",outcome="missing_secret"} 1',
            before,
        )
        self.assertNotIn('platform_boundary_event_producer_total', unavailable)
        self.assertIn(
            'platform_boundary_event_producer_probe_errors{service="id"} 1',
            unavailable,
        )
