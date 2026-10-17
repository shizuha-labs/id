"""
Unit tests for the step-up token core (HIVE-6 / HLD page 7197343e, v1.0).

These pin the *load-bearing* security invariants of ``identity/stepup.py`` that
the HLD freezes: the RS256 mint/verify round-trip, the scope tuple match, the
single-use jti deny-list, the A7 (a) ``cnf.ath`` session binding, the §4.2
action→factor-strength floor, and the §8a TOTP single-mint marker.

The Redis client is faked (a tiny in-process SET-NX store) so the tests are pure
logic with no Redis/DB dependency — same style as ``test_link_issues.py``. Django
settings are configured minimally so ``django.conf.settings`` resolves without a
full project boot.
"""
import base64
import hashlib
import time
import unittest
from unittest import mock

import django
from django.conf import settings

if not settings.configured:
    settings.configure(
        DEBUG=True,
        STEP_UP_ACTION_POLICY={
            'hard-delete': {'ttl_s': 60, 'min_factor': 'totp'},
            'export': {'ttl_s': 300, 'min_factor': 'totp'},
            'rename': {'ttl_s': 60, 'min_factor': 'totp'},
            'dashboard': {'ttl_s': 300, 'min_factor': 'totp'},
        },
        USE_TZ=True,
    )
    django.setup()

from identity import stepup  # noqa: E402

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


class FakeRedis:
    """Minimal SET NX EX store with controllable clock for TTL behaviour."""

    def __init__(self):
        self.store = {}  # key -> expiry_epoch

    def set(self, key, value, nx=False, ex=None):
        now = time.time()
        # drop expired
        if key in self.store and self.store[key] <= now:
            del self.store[key]
        if nx and key in self.store:
            return None
        self.store[key] = now + (ex or 0)
        return True


def _patch_redis(fake):
    return mock.patch.object(stepup, '_get_client', return_value=fake)


class TokenRoundTripTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeRedis()
        self.scope = stepup.StepUpScope(owner_id=42, resource_id='claw_abc', action='export')

    def test_mint_then_verify_valid_and_single_use(self):
        token, jti, _exp = stepup.mint_step_up_token(self.scope, ttl_s=300)
        with _patch_redis(self.fake):
            r1 = stepup.verify_step_up_token(token, self.scope.as_dict())
            self.assertTrue(r1.valid)
            self.assertEqual(r1.scope, self.scope.as_dict())
            # Replay: jti already consumed -> replayed.
            r2 = stepup.verify_step_up_token(token, self.scope.as_dict())
            self.assertFalse(r2.valid)
            self.assertEqual(r2.reason, 'replayed')

    def test_scope_mismatch_rejected(self):
        token, _jti, _exp = stepup.mint_step_up_token(self.scope, ttl_s=300)
        wrong = {'owner_id': 42, 'resource_id': 'claw_OTHER', 'action': 'export'}
        with _patch_redis(self.fake):
            r = stepup.verify_step_up_token(token, wrong)
        self.assertFalse(r.valid)
        self.assertEqual(r.reason, 'scope_mismatch')
        # A rejected verify must NOT consume the jti (no row written).
        self.assertEqual(self.fake.store, {})

    def test_expired_token_rejected(self):
        token, _jti, _exp = stepup.mint_step_up_token(self.scope, ttl_s=-1)
        with _patch_redis(self.fake):
            r = stepup.verify_step_up_token(token, self.scope.as_dict())
        self.assertFalse(r.valid)
        self.assertEqual(r.reason, 'expired')

    def test_garbage_token_unknown(self):
        with _patch_redis(self.fake):
            r = stepup.verify_step_up_token('not.a.jwt', self.scope.as_dict())
        self.assertFalse(r.valid)
        self.assertEqual(r.reason, 'unknown')


class SessionBindingTests(unittest.TestCase):
    """A7 (a): irreversible actions carry cnf.ath and must match session_binding."""

    def setUp(self):
        self.fake = FakeRedis()
        self.access_token = 'header.payload.signature'
        self.ath = base64.urlsafe_b64encode(
            hashlib.sha256(self.access_token.encode()).digest()
        ).rstrip(b'=').decode()
        self.scope = stepup.StepUpScope(owner_id=7, resource_id='claw_x', action='hard-delete')

    def test_ath_helper_matches_rfc9449_construction(self):
        self.assertEqual(stepup.access_token_ath(self.access_token), self.ath)

    def test_hard_delete_requires_matching_binding(self):
        token, _jti, _exp = stepup.mint_step_up_token(
            self.scope, ttl_s=60, session_ath=self.ath
        )
        with _patch_redis(self.fake):
            ok = stepup.verify_step_up_token(token, self.scope.as_dict(), session_binding=self.ath)
            self.assertTrue(ok.valid)

    def test_hard_delete_binding_mismatch_rejected(self):
        token, _jti, _exp = stepup.mint_step_up_token(
            self.scope, ttl_s=60, session_ath=self.ath
        )
        with _patch_redis(self.fake):
            bad = stepup.verify_step_up_token(
                token, self.scope.as_dict(), session_binding='rotated-token-ath'
            )
        self.assertFalse(bad.valid)
        self.assertEqual(bad.reason, 'binding_mismatch')

    def test_missing_binding_for_irreversible_rejected(self):
        token, _jti, _exp = stepup.mint_step_up_token(
            self.scope, ttl_s=60, session_ath=self.ath
        )
        with _patch_redis(self.fake):
            r = stepup.verify_step_up_token(token, self.scope.as_dict(), session_binding='')
        self.assertFalse(r.valid)
        self.assertEqual(r.reason, 'binding_mismatch')

    def test_reversible_action_ignores_binding(self):
        scope = stepup.StepUpScope(owner_id=7, resource_id='claw_x', action='export')
        token, _jti, _exp = stepup.mint_step_up_token(scope, ttl_s=300)
        with _patch_redis(self.fake):
            # No session_binding supplied; reversible action has no cnf -> valid.
            r = stepup.verify_step_up_token(token, scope.as_dict())
        self.assertTrue(r.valid)


class FactorFloorTests(unittest.TestCase):
    """§4.2: a presented factor weaker than the action's floor is refused."""

    def test_totp_meets_totp_floor(self):
        self.assertTrue(stepup.factor_meets_floor('totp', 'hard-delete'))

    def test_password_below_totp_floor(self):
        self.assertFalse(stepup.factor_meets_floor('password', 'hard-delete'))

    def test_webauthn_exceeds_totp_floor(self):
        self.assertTrue(stepup.factor_meets_floor('webauthn', 'export'))

    def test_unknown_action_has_no_floor(self):
        self.assertFalse(stepup.factor_meets_floor('totp', 'no-such-action'))

    def test_prod_gate_blocks_password_when_not_debug(self):
        with mock.patch.object(settings, 'DEBUG', False), \
             mock.patch.object(settings, 'STEP_UP_ALLOW_PASSWORD_BACKEND', False, create=True):
            self.assertFalse(stepup.prod_gate_ok('password', 'hard-delete'))
            # totp is unaffected by the password prod-gate.
            self.assertTrue(stepup.prod_gate_ok('totp', 'hard-delete'))

    def test_prod_gate_allows_password_in_debug(self):
        with mock.patch.object(settings, 'DEBUG', True):
            self.assertTrue(stepup.prod_gate_ok('password', 'hard-delete'))


class StepUpTokenFactorProofTests(unittest.TestCase):
    """HIVE-20 re-enroll proof must be bound to satisfied factor strength."""

    def setUp(self):
        self.fake = FakeRedis()
        self.scope = stepup.StepUpScope(
            owner_id=42, resource_id='step-up-enrollment', action='factor-reenroll',
        )

    def test_min_factor_rejects_totp_backed_token_for_webauthn_owner(self):
        token, _jti, _exp = stepup.mint_step_up_token(
            self.scope, ttl_s=120, factor='totp',
        )
        with _patch_redis(self.fake):
            result = stepup.verify_step_up_token(
                token, self.scope.as_dict(), min_factor='webauthn',
            )
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, 'factor_below_floor')
        # A weak proof must not consume the token's jti as a side effect.
        self.assertEqual(self.fake.store, {})

    def test_min_factor_accepts_webauthn_backed_token_for_webauthn_owner(self):
        token, _jti, _exp = stepup.mint_step_up_token(
            self.scope, ttl_s=120, factor='webauthn',
        )
        with _patch_redis(self.fake):
            result = stepup.verify_step_up_token(
                token, self.scope.as_dict(), min_factor='webauthn',
            )
        self.assertTrue(result.valid)
        self.assertEqual(result.scope, self.scope.as_dict())
        self.assertEqual(result.factor, 'webauthn')

    def test_min_factor_fails_closed_when_token_has_no_factor_claim(self):
        token, _jti, _exp = stepup.mint_step_up_token(self.scope, ttl_s=120)
        with _patch_redis(self.fake):
            result = stepup.verify_step_up_token(
                token, self.scope.as_dict(), min_factor='totp',
            )
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, 'factor_below_floor')


class JtiDenyListTests(unittest.TestCase):
    def test_claim_jti_is_single_winner(self):
        fake = FakeRedis()
        with _patch_redis(fake):
            self.assertTrue(stepup.claim_jti('jti-1', 60))
            self.assertFalse(stepup.claim_jti('jti-1', 60))  # replay


class TotpSingleMintTests(unittest.TestCase):
    """§8a: a TOTP code is consumable once per (device, time_step)."""

    def test_step_claim_single_winner(self):
        fake = FakeRedis()
        with _patch_redis(fake):
            self.assertTrue(stepup._claim_totp_step(device_id=99, time_step=1000))
            self.assertFalse(stepup._claim_totp_step(device_id=99, time_step=1000))
            # different step / device still mints.
            self.assertTrue(stepup._claim_totp_step(device_id=99, time_step=1001))
            self.assertTrue(stepup._claim_totp_step(device_id=100, time_step=1000))


class WebAuthnBackendTests(unittest.TestCase):
    """HIVE-20: WebAuthn registers as a SecondFactor without wire changes."""

    class FakeDevice:
        id = 77
        confirmed = True
        webauthn_credential_data = 'stored-credential'

        def __init__(self):
            self.saved = []

        def save(self, update_fields=None):
            self.saved.append(tuple(update_fields or ()))

    class FakeChallenge:
        webauthn_state = {'challenge': 'state'}

    def test_webauthn_factor_is_registered(self):
        self.assertEqual(stepup.get_factor('webauthn').name, 'webauthn')
        self.assertTrue(stepup.factor_meets_floor('webauthn', 'hard-delete'))

    def test_webauthn_assertion_verification_persists_updated_credential(self):
        device = self.FakeDevice()
        updated_credential = object()
        fake_server = mock.Mock()
        fake_server.authenticate_complete.return_value = updated_credential

        with mock.patch.object(stepup, 'webauthn_credential_from_device', return_value='credential'), \
             mock.patch.object(stepup, '_webauthn_server', return_value=fake_server), \
             mock.patch.object(stepup, '_encode_webauthn_credential', return_value='updated'):
            ok = stepup.get_factor('webauthn').verify(
                device=device, answer={'id': 'assertion'}, challenge=self.FakeChallenge(),
            )

        self.assertTrue(ok)
        fake_server.authenticate_complete.assert_called_once_with(
            {'challenge': 'state'}, ['credential'], {'id': 'assertion'},
        )
        self.assertEqual(device.webauthn_credential_data, 'updated')
        self.assertEqual(device.saved, [('webauthn_credential_data', 'updated_at')])

    def test_webauthn_assertion_requires_challenge_state(self):
        challenge = self.FakeChallenge()
        challenge.webauthn_state = {}
        with mock.patch.object(stepup, 'webauthn_credential_from_device', return_value='credential'):
            ok = stepup.get_factor('webauthn').verify(
                device=self.FakeDevice(), answer={'id': 'assertion'}, challenge=challenge,
            )
        self.assertFalse(ok)

    def test_webauthn_registration_begin_returns_public_key_options(self):
        user = mock.Mock(pk=42, email='owner@example.com', username='owner')
        options, state = stepup.webauthn_registration_begin(user)

        self.assertIn('publicKey', options)
        self.assertEqual(options['publicKey']['rp']['name'], 'Shizuha ID')
        self.assertEqual(options['publicKey']['user']['name'], 'owner@example.com')
        self.assertIn('challenge', state)

    def test_webauthn_origin_allowlist_fails_closed_when_empty(self):
        with mock.patch.object(settings, 'WEBAUTHN_ALLOWED_ORIGINS', [], create=True):
            self.assertFalse(stepup.webauthn_origin_allowed('https://erp.shizuha.com'))
            self.assertFalse(stepup.webauthn_origin_allowed('https://attacker.example'))
            self.assertFalse(stepup.webauthn_origin_allowed(''))

    def test_webauthn_origin_allowlist_accepts_only_configured_origin(self):
        with mock.patch.object(
            settings,
            'WEBAUTHN_ALLOWED_ORIGINS',
            ['https://erp.shizuha.com'],
            create=True,
        ):
            self.assertTrue(stepup.webauthn_origin_allowed('https://erp.shizuha.com'))
            self.assertFalse(stepup.webauthn_origin_allowed('https://attacker.example'))


if __name__ == '__main__':
    unittest.main()


from django.test import TestCase as DjangoTestCase, override_settings as django_override_settings  # noqa: E402


class Login2FATests(DjangoTestCase):
    """PLAT-493: password success yields only pending login until 2FA passes."""

    def setUp(self):
        from django.contrib.auth import get_user_model
        from rest_framework.test import APIClient
        from identity.models import UserProfile

        self.client = APIClient()
        User = get_user_model()
        self.user = User.objects.create_user(
            username='mfauser', email='mfa@example.com', password='correct-password'
        )
        UserProfile.objects.get_or_create(user=self.user)

    @django_override_settings(TWOFA_LOGIN_ENFORCEMENT='nudge')
    def test_enrolled_user_gets_pending_token_then_totp_completes_session(self):
        import pyotp
        from identity.models import TOTPDevice

        secret = pyotp.random_base32()
        TOTPDevice.objects.create(
            user=self.user,
            device_type=TOTPDevice.DEVICE_TOTP,
            secret=secret,
            confirmed=True,
        )

        login = self.client.post('/api/auth/login/', {
            'username': 'mfauser',
            'password': 'correct-password',
        }, format='json')

        self.assertEqual(login.status_code, 202)
        self.assertEqual(login.data['status'], '2fa_required')
        self.assertIn('totp', login.data['factors'])
        self.assertNotIn('tokens', login.data)

        code = pyotp.TOTP(secret).now()
        with _patch_redis(FakeRedis()):
            complete = self.client.post('/api/auth/login/2fa/', {
                'pending_token': login.data['pending_token'],
                'factor': 'totp',
                'answer': code,
            }, format='json')

            self.assertEqual(complete.status_code, 200)
            self.assertIn('tokens', complete.data)
            self.assertEqual(complete.data['amr'], ['pwd', 'totp'])

            replay = self.client.post('/api/auth/login/2fa/', {
                'pending_token': login.data['pending_token'],
                'factor': 'totp',
                'answer': code,
            }, format='json')
        self.assertEqual(replay.status_code, 400)

    @django_override_settings(TWOFA_LOGIN_ENFORCEMENT='nudge')
    def test_recovery_code_is_single_use_login_factor(self):
        from identity.models import RecoveryCode, TOTPDevice

        TOTPDevice.objects.create(user=self.user, device_type=TOTPDevice.DEVICE_TOTP, secret='ABC', confirmed=True)
        codes = RecoveryCode.regenerate_for_user(self.user, count=1)

        login = self.client.post('/api/auth/login/', {
            'username': 'mfauser',
            'password': 'correct-password',
        }, format='json')
        self.assertEqual(login.status_code, 202)
        self.assertIn('recovery', login.data['factors'])

        complete = self.client.post('/api/auth/login/2fa/', {
            'pending_token': login.data['pending_token'],
            'factor': 'recovery',
            'answer': codes[0],
        }, format='json')
        self.assertEqual(complete.status_code, 200)
        self.assertEqual(complete.data['amr'], ['pwd', 'recovery'])

        second_login = self.client.post('/api/auth/login/', {
            'username': 'mfauser',
            'password': 'correct-password',
        }, format='json')
        reused = self.client.post('/api/auth/login/2fa/', {
            'pending_token': second_login.data['pending_token'],
            'factor': 'recovery',
            'answer': codes[0],
        }, format='json')
        self.assertEqual(reused.status_code, 403)

    @django_override_settings(TWOFA_LOGIN_ENFORCEMENT='enforce')
    def test_enforced_unenrolled_user_cannot_get_password_only_session(self):
        profile = self.user.profile
        profile.twofa_enforced = True
        profile.save(update_fields=['twofa_enforced'])

        response = self.client.post('/api/auth/login/', {
            'username': 'mfauser',
            'password': 'correct-password',
        }, format='json')

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data['error'], '2fa_enrollment_required')
        self.assertNotIn('tokens', response.data)

    @django_override_settings(TWOFA_LOGIN_ENFORCEMENT='nudge', TWOFA_LOGIN_MAX_ATTEMPTS=2)
    def test_login_2fa_locks_pending_token_after_failed_attempts(self):
        import pyotp
        from identity.models import TOTPDevice

        secret = pyotp.random_base32()
        TOTPDevice.objects.create(
            user=self.user, device_type=TOTPDevice.DEVICE_TOTP, secret=secret, confirmed=True,
        )
        login = self.client.post('/api/auth/login/', {
            'username': 'mfauser',
            'password': 'correct-password',
        }, format='json')
        self.assertEqual(login.status_code, 202)

        first = self.client.post('/api/auth/login/2fa/', {
            'pending_token': login.data['pending_token'],
            'factor': 'totp',
            'answer': '000000',
        }, format='json')
        self.assertEqual(first.status_code, 403)

        second = self.client.post('/api/auth/login/2fa/', {
            'pending_token': login.data['pending_token'],
            'factor': 'totp',
            'answer': '000000',
        }, format='json')
        self.assertEqual(second.status_code, 429)
        self.assertEqual(second.data['error'], 'second_factor_locked')

        with _patch_redis(FakeRedis()):
            locked = self.client.post('/api/auth/login/2fa/', {
                'pending_token': login.data['pending_token'],
                'factor': 'totp',
                'answer': pyotp.TOTP(secret).now(),
            }, format='json')
        self.assertEqual(locked.status_code, 429)
        self.assertNotIn('tokens', locked.data)

    def test_totp_enrollment_confirm_requires_live_code_before_enabling(self):
        import pyotp
        from unittest import mock
        from identity.models import TOTPDevice, StepUpEnrollmentToken

        secret = pyotp.random_base32()
        device = TOTPDevice.objects.create(
            user=self.user, device_type=TOTPDevice.DEVICE_TOTP, secret=secret, confirmed=False,
        )
        token = StepUpEnrollmentToken.create_for_device(
            device, purpose=StepUpEnrollmentToken.PURPOSE_FIRST_ENROLL, ip_address='127.0.0.1',
        )

        missing = self.client.post('/api/auth/step-up/enroll/confirm/', {'token': token.token}, format='json')
        self.assertEqual(missing.status_code, 400)
        device.refresh_from_db()
        self.assertFalse(device.confirmed)

        bad = self.client.post('/api/auth/step-up/enroll/confirm/', {
            'token': token.token,
            'code': '000000',
        }, format='json')
        self.assertEqual(bad.status_code, 403)
        device.refresh_from_db()
        self.assertFalse(device.confirmed)

        with _patch_redis(FakeRedis()), \
             mock.patch('identity.stepup_views.send_step_up_notification_email'):
            ok = self.client.post('/api/auth/step-up/enroll/confirm/', {
                'token': token.token,
                'code': pyotp.TOTP(secret).now(),
            }, format='json')
        self.assertEqual(ok.status_code, 200)
        self.assertTrue(ok.data['confirmed'])
        self.assertTrue(ok.data['recovery_codes'])
        device.refresh_from_db()
        self.assertTrue(device.confirmed)


    @django_override_settings(STEP_UP_ENROLL_CONFIRM_MAX_ATTEMPTS=2)
    def test_totp_enrollment_confirm_locks_after_missing_and_bad_code(self):
        import pyotp
        from identity.models import TOTPDevice, StepUpEnrollmentToken

        secret = pyotp.random_base32()
        device = TOTPDevice.objects.create(
            user=self.user, device_type=TOTPDevice.DEVICE_TOTP, secret=secret, confirmed=False,
        )
        token = StepUpEnrollmentToken.create_for_device(
            device, purpose=StepUpEnrollmentToken.PURPOSE_FIRST_ENROLL, ip_address='127.0.0.1',
        )

        missing = self.client.post('/api/auth/step-up/enroll/confirm/', {'token': token.token}, format='json')
        self.assertEqual(missing.status_code, 400)

        bad = self.client.post('/api/auth/step-up/enroll/confirm/', {
            'token': token.token,
            'code': '000000',
        }, format='json')
        self.assertEqual(bad.status_code, 429)
        self.assertEqual(bad.data['error'], 'invalid totp code')

        with _patch_redis(FakeRedis()):
            locked = self.client.post('/api/auth/step-up/enroll/confirm/', {
                'token': token.token,
                'code': pyotp.TOTP(secret).now(),
            }, format='json')
        self.assertEqual(locked.status_code, 429)
        self.assertEqual(locked.data['error'], 'enrollment confirmation locked')
        device.refresh_from_db()
        token.refresh_from_db()
        self.assertFalse(device.confirmed)
        self.assertIsNone(token.used_at)

    def test_recovery_code_regeneration_requires_current_factor(self):
        import pyotp
        from identity.models import TOTPDevice

        secret = pyotp.random_base32()
        TOTPDevice.objects.create(
            user=self.user, device_type=TOTPDevice.DEVICE_TOTP, secret=secret, confirmed=True,
        )
        self.client.force_authenticate(self.user)

        password_only = self.client.post('/api/auth/step-up/recovery-codes/regenerate/', {
            'password': 'correct-password',
        }, format='json')
        self.assertEqual(password_only.status_code, 403)
        self.assertEqual(password_only.data['error'], 'current confirmed factor required')

        with _patch_redis(FakeRedis()):
            ok = self.client.post('/api/auth/step-up/recovery-codes/regenerate/', {
                'password': 'correct-password',
                'current_code': pyotp.TOTP(secret).now(),
            }, format='json')
        self.assertEqual(ok.status_code, 200)
        self.assertTrue(ok.data['recovery_codes'])

class PasswordLoginLockoutTests(DjangoTestCase):
    """PLAT-495: password step has progressive lockout before 2FA."""

    def setUp(self):
        from django.contrib.auth import get_user_model
        from django.core.cache import cache
        from rest_framework.test import APIClient
        cache.clear()
        self.client = APIClient()
        User = get_user_model()
        User.objects.create_user(username='lockme', email='lockme@example.com', password='correct-password')

    @django_override_settings(
        LOGIN_PASSWORD_MAX_ATTEMPTS=2,
        LOGIN_PASSWORD_WINDOW_SECONDS=300,
        LOGIN_PASSWORD_BASE_LOCKOUT_SECONDS=60,
        LOGIN_PASSWORD_MAX_LOCKOUT_SECONDS=300,
        TWOFA_LOGIN_ENFORCEMENT='nudge',
    )
    def test_password_failures_lock_before_session_or_pending_2fa(self):
        first = self.client.post('/api/auth/login/', {
            'username': 'lockme', 'password': 'wrong-password',
        }, format='json')
        self.assertEqual(first.status_code, 401)

        second = self.client.post('/api/auth/login/', {
            'username': 'lockme', 'password': 'wrong-password',
        }, format='json')
        self.assertEqual(second.status_code, 429)
        self.assertEqual(second.data['error'], 'too_many_login_attempts')

        locked_even_with_correct_password = self.client.post('/api/auth/login/', {
            'username': 'lockme', 'password': 'correct-password',
        }, format='json')
        self.assertEqual(locked_even_with_correct_password.status_code, 429)
        self.assertNotIn('tokens', locked_even_with_correct_password.data)
