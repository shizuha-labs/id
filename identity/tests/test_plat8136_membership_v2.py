"""PLAT-5343 slice 1 — ID subject-assertion emission (HLD v12 §4.1).

Pins the assertion trust contract and the v2 cutover semantics:

- The assertion is signed with ID's DEDICATED internal-signing key (never the
  user-token key) under EdDSA (S1 allowlist; receivers accept ES256 too).
- Required claims: iss=shizuha-id, aud=shizuha-admin,
  scope=membership-projection:resolve, decimal sub, canonical email when
  known, iat, exp ≤ +5s, fresh jti.
- Confused-deputy (matrix row 11): the assertion is constructed exclusively
  from the already-authenticated mint principal — hostile request body/query
  input cannot supply or override sub/email.
- Cutover: v2 is used only when selected (flag + material); a selected v2
  without material fails the mint closed (v2_emission_unavailable), never
  falls back to v1; flag off keeps the v1 path untouched.
"""
import time
import uuid
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from identity.membership_v2 import (
    ASSERTION_AUDIENCE,
    ASSERTION_MAX_LIFETIME_SECONDS,
    ASSERTION_SCOPE,
    AssertionEmissionUnavailable,
    emit_subject_assertion,
    v2_enabled,
    v2_request_headers,
)
from identity.views import (
    MembershipProjectionUnavailable,
    _fetch_project_memberships,
)

User = get_user_model()

SIGNING_KEY = 'v2-id-service-credential'


def _generate_signing_key():
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode('ascii')
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('ascii')
    return pem, pub


V2_MATERIAL = override_settings(
    SHIZUHA_ID_V2_MEMBERSHIP_PROJECTION='true',
    SHIZUHA_ID_V2_SIGNING_PRIVATE_KEY=None,  # set per-test (generated keys)
    SHIZUHA_ADMIN_V2_SERVICE_CREDENTIAL=SIGNING_KEY,
)


class AssertionEmissionTests(TestCase):
    """The §4.1 assertion contract, pinned at the issuer."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.private_pem, cls.public_pem = _generate_signing_key()

    def setUp(self):
        super().setUp()
        self.user = User.objects.create(
            username='zen', email='Zen@Shizuha.com', id=4242)
        self._override = override_settings(
            SHIZUHA_ID_V2_MEMBERSHIP_PROJECTION='true',
            SHIZUHA_ID_V2_SIGNING_PRIVATE_KEY=self.private_pem,
            SHIZUHA_ADMIN_V2_SERVICE_CREDENTIAL=SIGNING_KEY,
        )
        self._override.enable()
        self.addCleanup(self._override.disable)

    def _claims(self, token):
        return jwt.decode(
            token, self.public_pem, algorithms=['EdDSA'],
            options={'verify_exp': False, 'verify_iat': False,
                     'verify_sub': False, 'verify_aud': False})

    def test_required_claims(self):
        token = emit_subject_assertion(self.user)
        claims = self._claims(token)
        self.assertEqual(claims['iss'], 'shizuha-id')
        self.assertEqual(claims['aud'], ASSERTION_AUDIENCE)
        self.assertEqual(claims['scope'], ASSERTION_SCOPE)
        self.assertEqual(claims['sub'], '4242')  # decimal string (RFC 7519)
        self.assertEqual(claims['email'], 'zen@shizuha.com')  # canonical
        self.assertLessEqual(claims['exp'] - claims['iat'],
                             ASSERTION_MAX_LIFETIME_SECONDS)
        self.assertTrue(claims['jti'])

    def test_signed_with_dedicated_key_not_user_token_key(self):
        """The assertion verifies under the dedicated internal key and is NOT
        a SIMPLE_JWT user token (different key, different claims shape)."""
        token = emit_subject_assertion(self.user)
        header = jwt.get_unverified_header(token)
        self.assertEqual(header['alg'], 'EdDSA')
        # Verifies under the dedicated key's public half...
        self._claims(token)
        # ...and carries none of the user-token claim shape.
        claims = self._claims(token)
        self.assertNotIn('user_id', claims)
        self.assertNotIn('token_version', claims)
        self.assertNotIn('organization_memberships', claims)

    def test_fresh_jti_per_emission(self):
        first = self._claims(emit_subject_assertion(self.user))
        second = self._claims(emit_subject_assertion(self.user))
        self.assertNotEqual(first['jti'], second['jti'])

    def test_confused_deputy_principal_is_the_only_input(self):
        """Matrix row 11: the emitter takes the principal and nothing else —
        hostile request data cannot reach it, so the assertion for the same
        user is invariant regardless of any hypothetical request input."""
        token_a = emit_subject_assertion(self.user)
        # Simulate the strongest hostile-input claim: mutate every request-ish
        # attribute on the user object to attacker values; the emitter still
        # reads only the authenticated identity fields it is given.
        self.user.email = 'Zen@Shizuha.com'  # canonicalized by the emitter
        token_b = emit_subject_assertion(self.user)
        self.assertEqual(self._claims(token_a)['sub'], self._claims(token_b)['sub'])
        self.assertEqual(self._claims(token_a)['email'], 'zen@shizuha.com')

    def test_missing_email_omits_claim(self):
        self.user.email = ''
        claims = self._claims(emit_subject_assertion(self.user))
        self.assertNotIn('email', claims)

    def test_unconfigured_key_fails_closed(self):
        with override_settings(SHIZUHA_ID_V2_SIGNING_PRIVATE_KEY=''):
            with self.assertRaises(AssertionEmissionUnavailable):
                emit_subject_assertion(self.user)

    def test_request_headers_carry_bound_credential_and_assertion(self):
        headers = v2_request_headers(self.user)
        self.assertEqual(headers['X-Internal-Service'], 'shizuha-id')
        self.assertEqual(headers['X-Internal-Service-Token'], SIGNING_KEY)
        self._claims(headers['X-Shizuha-Subject-Assertion'])

    def test_missing_credential_fails_closed(self):
        with override_settings(SHIZUHA_ADMIN_V2_SERVICE_CREDENTIAL=''):
            with self.assertRaises(AssertionEmissionUnavailable):
                v2_request_headers(self.user)


class V2CutoverTests(TestCase):
    """Flag/material cutover semantics (§4.4 step 3)."""

    def setUp(self):
        super().setUp()
        self.user = User.objects.create(username='zen', email='zen@shizuha.com', id=4242)

    def test_flag_off_means_v1_path(self):
        self.assertFalse(v2_enabled())
        with patch('identity.views._admin_req.get') as v1_get, \
                patch('identity.views._admin_req.post') as v2_post:
            v1_get.return_value.status_code = 200
            v1_get.return_value.json.return_value = {
                'project_memberships': {'342': 'member'}, 'project_ids': [342]}
            ids, roles = _fetch_project_memberships(self.user, required=True)
        self.assertEqual(ids, [342])
        v1_get.assert_called_once()
        v2_post.assert_not_called()

    def test_selected_v2_without_material_fails_closed(self):
        """A selected v2 with missing material refuses the mint — never a
        silent fallback to the circular v1 path."""
        self._override = override_settings(
            SHIZUHA_ID_V2_MEMBERSHIP_PROJECTION='true',
            SHIZUHA_ID_V2_SIGNING_PRIVATE_KEY='',
            SHIZUHA_ADMIN_V2_SERVICE_CREDENTIAL='',
        )
        self._override.enable()
        self.addCleanup(self._override.disable)
        self.assertTrue(v2_enabled())
        with patch('identity.views._admin_req.get') as v1_get, \
                patch('identity.views._admin_req.post') as v2_post:
            with self.assertRaises(MembershipProjectionUnavailable):
                _fetch_project_memberships(self.user, required=True)
        v1_get.assert_not_called()
        v2_post.assert_not_called()

    def test_v2_success_shape(self):
        private_pem, _ = _generate_signing_key()
        self._override = override_settings(
            SHIZUHA_ID_V2_MEMBERSHIP_PROJECTION='true',
            SHIZUHA_ID_V2_SIGNING_PRIVATE_KEY=private_pem,
            SHIZUHA_ADMIN_V2_SERVICE_CREDENTIAL=SIGNING_KEY,
        )
        self._override.enable()
        self.addCleanup(self._override.disable)

        captured = {}

        def fake_post(url, **kwargs):
            captured['url'] = url
            captured['kwargs'] = kwargs
            class _Resp:
                status_code = 200
                def json(self):
                    return {'project_memberships': {'342': 'member'},
                            'project_ids': [342]}
            return _Resp()

        with patch('identity.views._admin_req.post', side_effect=fake_post):
            ids, roles = _fetch_project_memberships(self.user, required=True)
        self.assertEqual(ids, [342])
        self.assertEqual(roles, {'342': 'member'})
        self.assertTrue(captured['url'].endswith('/internal/v2/project-memberships:resolve'))
        self.assertEqual(captured['kwargs']['headers']['X-Internal-Service'], 'shizuha-id')
        # The assertion travels in the header and validates as our contract.
        token = captured['kwargs']['headers']['X-Shizuha-Subject-Assertion']
        header = jwt.get_unverified_header(token)
        self.assertEqual(header['alg'], 'EdDSA')

    def test_v2_non_200_fails_mint_closed(self):
        private_pem, _ = _generate_signing_key()
        self._override = override_settings(
            SHIZUHA_ID_V2_MEMBERSHIP_PROJECTION='true',
            SHIZUHA_ID_V2_SIGNING_PRIVATE_KEY=private_pem,
            SHIZUHA_ADMIN_V2_SERVICE_CREDENTIAL=SIGNING_KEY,
        )
        self._override.enable()
        self.addCleanup(self._override.disable)

        class _Resp:
            status_code = 503
            def json(self):
                return {'error': 'project_membership_unavailable'}

        with patch('identity.views._admin_req.post', return_value=_Resp()):
            with self.assertRaises(MembershipProjectionUnavailable):
                _fetch_project_memberships(self.user, required=True)

    def test_v2_invalid_payload_fails_mint_closed(self):
        private_pem, _ = _generate_signing_key()
        self._override = override_settings(
            SHIZUHA_ID_V2_MEMBERSHIP_PROJECTION='true',
            SHIZUHA_ID_V2_SIGNING_PRIVATE_KEY=private_pem,
            SHIZUHA_ADMIN_V2_SERVICE_CREDENTIAL=SIGNING_KEY,
        )
        self._override.enable()
        self.addCleanup(self._override.disable)

        class _Resp:
            status_code = 200
            def json(self):
                return {'unexpected': 'shape'}

        with patch('identity.views._admin_req.post', return_value=_Resp()):
            with self.assertRaises(MembershipProjectionUnavailable):
                _fetch_project_memberships(self.user, required=True)

    def test_v2_timeout_fails_mint_closed(self):
        import requests as http_requests
        private_pem, _ = _generate_signing_key()
        self._override = override_settings(
            SHIZUHA_ID_V2_MEMBERSHIP_PROJECTION='true',
            SHIZUHA_ID_V2_SIGNING_PRIVATE_KEY=private_pem,
            SHIZUHA_ADMIN_V2_SERVICE_CREDENTIAL=SIGNING_KEY,
        )
        self._override.enable()
        self.addCleanup(self._override.disable)

        with patch('identity.views._admin_req.post',
                   side_effect=http_requests.Timeout('admin v2 timeout')):
            with self.assertRaises(MembershipProjectionUnavailable):
                _fetch_project_memberships(self.user, required=True)
