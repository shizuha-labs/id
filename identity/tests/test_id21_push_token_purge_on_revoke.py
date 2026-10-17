"""ID-21 (HLD 815412d1 §3.6): push tokens are bound to the issuing session and
purged on session revocation, so a revoked (logged-out / password-changed)
session stops receiving pushes — atomically with the access-cutoff bump.
"""
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate
from rest_framework_simplejwt.tokens import AccessToken

from identity.models import PushToken, UserProfile
from identity.views import RegisterPushTokenView, revoke_all_user_tokens

User = get_user_model()


class PushTokenPurgeOnRevokeTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='alice', password='pw', email='alice@shizuha.com')
        self.other = User.objects.create_user(username='bob', password='pw', email='bob@shizuha.com')

    def _push(self, user, device, active=True, jti=''):
        return PushToken.objects.create(
            user=user, token=f'ExponentPushToken[{device}]', device_id=device,
            platform='android', is_active=active, session_jti=jti,
        )

    def test_revoke_deactivates_users_push_tokens(self):
        a1 = self._push(self.user, 'dev-a1', jti='sess-1')
        a2 = self._push(self.user, 'dev-a2', jti='sess-2')
        b1 = self._push(self.other, 'dev-b1')  # different user — must be untouched

        revoke_all_user_tokens(self.user)

        a1.refresh_from_db(); a2.refresh_from_db(); b1.refresh_from_db()
        self.assertFalse(a1.is_active)
        self.assertFalse(a2.is_active)
        self.assertTrue(b1.is_active)  # another user's pushes unaffected

    def test_revoke_is_atomic_with_cutoff_bump(self):
        # The cutoff bump and the push purge happen together — after revoke, both
        # the cutoff is set AND the push tokens are deactivated (no partial state).
        self._push(self.user, 'dev-a1')
        before = timezone.now()
        revoke_all_user_tokens(self.user)
        prof = UserProfile.objects.get(user=self.user)
        self.assertIsNotNone(prof.access_revoked_before)
        self.assertGreaterEqual(prof.access_revoked_before, before)
        self.assertEqual(PushToken.objects.filter(user=self.user, is_active=True).count(), 0)

    def test_already_inactive_push_token_left_alone(self):
        inactive = self._push(self.user, 'dev-old', active=False)
        revoke_all_user_tokens(self.user)
        inactive.refresh_from_db()
        self.assertFalse(inactive.is_active)  # still inactive, no error

    def test_session_jti_association_persists(self):
        p = self._push(self.user, 'dev-a1', jti='abc123jti')
        p.refresh_from_db()
        self.assertEqual(p.session_jti, 'abc123jti')

    def test_no_push_tokens_is_noop(self):
        revoke_all_user_tokens(self.user)  # must not raise with zero push tokens


class RegisterBindsSessionJtiTests(TestCase):
    """ID-21 (review P2): the session_jti binding in RegisterPushTokenView.post
    is the key deliverable alongside the purge — exercise the registration view
    end-to-end so a future change that drops the jti capture is caught."""

    def setUp(self):
        self.user = User.objects.create_user(username='carol', password='pw', email='carol@shizuha.com')
        self.factory = APIRequestFactory()

    def _register(self, token_value, device_id, auth_token):
        request = self.factory.post(
            '/push-token/',
            {'token': token_value, 'device_id': device_id, 'platform': 'android'},
            format='json',
        )
        # force_authenticate's `token` kwarg becomes request.auth — exactly what
        # the view reads jti from.
        force_authenticate(request, user=self.user, token=auth_token)
        return RegisterPushTokenView.as_view()(request)

    def test_register_binds_session_jti_from_token(self):
        access = AccessToken.for_user(self.user)  # simplejwt always sets a jti claim
        access['sid'] = 'stable-session-family'
        jti = access['jti']
        self.assertTrue(jti)

        resp = self._register('ExponentPushToken[carol-dev]', 'carol-dev', access)
        self.assertIn(resp.status_code, (200, 201))

        pt = PushToken.objects.get(user=self.user, device_id='carol-dev')
        self.assertEqual(pt.session_jti, str(jti))
        self.assertEqual(pt.session_sid, 'stable-session-family')

    def test_register_without_jti_claim_sets_blank(self):
        # A validated token that carries no jti claim → best-effort capture yields ''.
        resp = self._register('ExponentPushToken[carol-dev2]', 'carol-dev2', {'token_type': 'access'})
        self.assertIn(resp.status_code, (200, 201))

        pt = PushToken.objects.get(user=self.user, device_id='carol-dev2')
        self.assertEqual(pt.session_jti, '')
        self.assertEqual(pt.session_sid, '')
