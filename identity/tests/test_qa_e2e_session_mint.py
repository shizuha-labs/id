"""ID-85/ID-86: typed, class-scoped ``qa_e2e_session_mint`` audit signal.

ren's security sign-off on ID-85 (PLAT-1247 gate) requires mint events for the
dedicated QA e2e principal class as a typed, filterable signal (answer A1),
with the class scope (condition C1) enforced by an explicit allowlist — the
normal login flow itself is unchanged for every principal.
"""
from unittest import mock

import jwt
from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase, override_settings
from rest_framework.request import Request
from rest_framework.test import APIClient

from identity.models import UserProfile
from identity.views import Login2FAView

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


@override_settings(
    TWOFA_LOGIN_ENFORCEMENT='off',
    QA_E2E_PRINCIPALS=('qa-e2e',),
)
class QaE2eSessionMintSignalTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        user_model = get_user_model()
        self.qa_e2e = user_model.objects.create_user(
            username='qa-e2e',
            email='qa-e2e@example.com',
            password='correct-password',
        )
        UserProfile.objects.get_or_create(user=self.qa_e2e)
        self.human = user_model.objects.create_user(
            username='humanuser',
            email='humanuser@example.com',
            password='correct-password',
        )
        UserProfile.objects.get_or_create(user=self.human)

    def _post_login(self, username):
        return self.client.post(
            '/api/auth/login/',
            {'username': username, 'password': 'correct-password'},
            format='json',
        )

    def test_login_of_qa_e2e_principal_emits_typed_mint_signal(self):
        with self.assertLogs('identity.audit', level='WARNING') as captured:
            response = self._post_login('qa-e2e')

        self.assertEqual(response.status_code, 200)
        self.assertIn('tokens', response.data)
        # The mint signal is additive: the browser-session cookies behave
        # exactly as on the uninstrumented login path.
        self.assertIn('shizuha-access-token', response.cookies)

        signals = [
            r.audit_signal for r in captured.records
            if getattr(r, 'audit_signal', {}).get('event_type') == 'qa_e2e_session_mint'
        ]
        self.assertEqual(len(signals), 1)
        signal = signals[0]
        self.assertEqual(signal['principal'], 'qa-e2e')
        self.assertEqual(signal['mint_path'], '/id/api/auth/login/')
        self.assertEqual(signal['actor'], 'anonymous:127.0.0.1')
        self.assertIn('timestamp', signal)
        claims = jwt.decode(
            response.data['tokens']['refresh'],
            options={'verify_signature': False},
        )
        self.assertEqual(signal['session_id'], claims['sid'])

    def test_login_of_non_class_principal_emits_no_mint_signal(self):
        # C1 (load-bearing): the allowlist is the ONLY class check — no other
        # principal's login may emit the QA class signal.
        with self.assertNoLogs('identity.audit', level='WARNING'):
            response = self._post_login('humanuser')

        self.assertEqual(response.status_code, 200)

    def test_empty_allowlist_disables_the_signal_entirely(self):
        with override_settings(QA_E2E_PRINCIPALS=()):
            with self.assertNoLogs('identity.audit', level='WARNING'):
                response = self._post_login('qa-e2e')

        self.assertEqual(response.status_code, 200)

    def test_2fa_completion_emits_typed_mint_signal(self):
        factory = RequestFactory()
        request = Request(factory.post(
            '/api/auth/login/2fa/', REMOTE_ADDR='127.0.0.1',
        ))
        view = Login2FAView()
        view.request = request

        with mock.patch(
            'identity.views.login_2fa.consume_pending_login_token',
            return_value=True,
        ), mock.patch(
            'identity.views.login_2fa.clear_failures',
        ):
            with self.assertLogs('identity.audit', level='WARNING') as captured:
                response = view._complete(self.qa_e2e, 'pending-token', 'recovery')

        self.assertEqual(response.status_code, 200)
        signals = [
            r.audit_signal for r in captured.records
            if getattr(r, 'audit_signal', {}).get('event_type') == 'qa_e2e_session_mint'
        ]
        self.assertEqual(len(signals), 1)
        signal = signals[0]
        self.assertEqual(signal['principal'], 'qa-e2e')
        self.assertEqual(signal['mint_path'], '/id/api/auth/login/2fa/')
        self.assertEqual(signal['actor'], 'anonymous:127.0.0.1')
