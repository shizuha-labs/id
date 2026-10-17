"""CTX-492 / CTX-497 v3: UserView RS256 read-bridge (Security-reviewed, Ren).

`/id/api/auth/user/` rejected the Cortex SSO RS256 token for every browser user
(Voice Lab "Start live" unauthorized). The fix is a single method-aware
composite authenticator on UserView:

- HS256 SimpleJWT authenticates on ALL verbs (unchanged behaviour).
- an RS256 SSO token authenticates on GET/HEAD ONLY, and only when the
  fail-closed positive predicate holds (access token; token_use absent or
  'sso_general'; client_id in the bounded allowlist). Revocation/is_active are
  enforced by the shared RS256 verifier.
- RS256 on PATCH (or any non-safe verb), or a delegated/unknown token, never
  authenticates → the mutation path stays HS256-only.

Pure-logic SimpleTestCase mirroring test_rs256_default_auth.py — the DB and the
RS256 verifier are mocked at their seams; this is the binding regression matrix
from the contract.
"""
from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings
from rest_framework.exceptions import AuthenticationFailed as DRFAuthFailed

from identity.authentication import UserViewScopedCompositeAuthentication

ALLOWED_CLIENT = 'cortex-sso-public'
_ALLOWLIST = (ALLOWED_CLIENT,)


def _request(method, header=b'Bearer rs256.tok.en'):
    return SimpleNamespace(
        method=method,
        META={'HTTP_AUTHORIZATION': header.decode()} if header else {},
    )


def _sso_payload(**over):
    p = {'user_id': 7, 'token_type': 'access', 'token_use': 'sso_general',
         'client_id': ALLOWED_CLIENT}
    p.update(over)
    return p


class PredicateTests(SimpleTestCase):
    @override_settings(RS256_USERINFO_ALLOWED_CLIENT_IDS=_ALLOWLIST)
    def test_positive_predicate_accepts_sso_general_allowed_client(self):
        self.assertTrue(UserViewScopedCompositeAuthentication._rs256_read_predicate(_sso_payload()))

    @override_settings(RS256_USERINFO_ALLOWED_CLIENT_IDS=_ALLOWLIST)
    def test_predicate_accepts_absent_token_use(self):
        p = _sso_payload()
        p.pop('token_use')
        self.assertTrue(UserViewScopedCompositeAuthentication._rs256_read_predicate(p))

    @override_settings(RS256_USERINFO_ALLOWED_CLIENT_IDS=_ALLOWLIST)
    def test_predicate_denies_delegated_and_unknown_token_use(self):
        for tu in ('mail_delegated', 'some_future_delegated', 'refresh'):
            self.assertFalse(
                UserViewScopedCompositeAuthentication._rs256_read_predicate(_sso_payload(token_use=tu)),
                tu,
            )

    @override_settings(RS256_USERINFO_ALLOWED_CLIENT_IDS=_ALLOWLIST)
    def test_predicate_denies_unlisted_or_absent_client(self):
        self.assertFalse(
            UserViewScopedCompositeAuthentication._rs256_read_predicate(_sso_payload(client_id='evil')))
        p = _sso_payload()
        p.pop('client_id')
        self.assertFalse(UserViewScopedCompositeAuthentication._rs256_read_predicate(p))

    @override_settings(RS256_USERINFO_ALLOWED_CLIENT_IDS=())
    def test_empty_allowlist_denies_everything(self):
        self.assertFalse(UserViewScopedCompositeAuthentication._rs256_read_predicate(_sso_payload()))


@override_settings(RS256_USERINFO_ALLOWED_CLIENT_IDS=_ALLOWLIST)
class MatrixTests(SimpleTestCase):
    def setUp(self):
        self.auth = UserViewScopedCompositeAuthentication()
        self.user = SimpleNamespace(pk=7, is_active=True)

    # --- HS256: all verbs authenticate (unchanged) --------------------------
    def _hs256(self, method):
        with patch('identity.authentication.OAuthClientRevocationJWTAuthentication.get_validated_token',
                   return_value={'user_id': 7, 'token_type': 'access'}), \
             patch('identity.authentication.User.objects.get', return_value=self.user):
            return self.auth.authenticate(_request(method))

    def test_hs256_get_authenticates(self):
        user, _ = self._hs256('GET')
        self.assertIs(user, self.user)

    def test_hs256_patch_authenticates(self):
        user, _ = self._hs256('PATCH')
        self.assertIs(user, self.user)

    # --- RS256 read bridge: GET/HEAD only, predicate-gated ------------------
    def _rs256(self, method, payload):
        # HS256 path misses (raises) → falls through to RS256 verifier (mocked).
        with patch('identity.authentication.OAuthClientRevocationJWTAuthentication.get_validated_token',
                   side_effect=Exception('not hs256')), \
             patch('identity.authentication._verify_rs256_access_token',
                   return_value=(self.user, payload)) as verify:
            result = self.auth.authenticate(_request(method))
        return result, verify

    def test_rs256_sso_get_authenticates_not_shadowed_by_hs256(self):
        # Authenticator-order proof: an RS256 GET reaches Path 2 and authenticates,
        # not aborted by the HS256 backend raising InvalidToken.
        result, verify = self._rs256('GET', _sso_payload())
        self.assertIsNotNone(result)
        self.assertIs(result[0], self.user)
        verify.assert_called_once()

    def test_rs256_sso_head_authenticates(self):
        result, _ = self._rs256('HEAD', _sso_payload())
        self.assertIsNotNone(result)

    def test_rs256_patch_never_reaches_verifier(self):
        # PATCH must not authenticate via RS256 and must not even verify it.
        result, verify = self._rs256('PATCH', _sso_payload())
        self.assertIsNone(result)
        verify.assert_not_called()

    def test_rs256_delegated_get_denied(self):
        result, _ = self._rs256('GET', _sso_payload(token_use='mail_delegated'))
        self.assertIsNone(result)

    def test_rs256_unlisted_client_get_denied(self):
        result, _ = self._rs256('GET', _sso_payload(client_id='evil'))
        self.assertIsNone(result)

    def test_revoked_client_rs256_get_denied_by_verifier(self):
        # The shared verifier raises on a revoked client → propagates as 401.
        with patch('identity.authentication.OAuthClientRevocationJWTAuthentication.get_validated_token',
                   side_effect=Exception('not hs256')), \
             patch('identity.authentication._verify_rs256_access_token',
                   side_effect=DRFAuthFailed('Token has been revoked.')):
            with self.assertRaises(DRFAuthFailed):
                self.auth.authenticate(_request('GET'))

    def test_voice_caller_repeated_get_loop_stays_authorized(self):
        # The production symptom: repeated GET validation must remain authorized
        # without ever widening to a mutation.
        for _ in range(5):
            result, _ = self._rs256('GET', _sso_payload())
            self.assertIsNotNone(result)

    def test_no_bearer_returns_none(self):
        self.assertIsNone(self.auth.authenticate(_request('GET', header=b'')))
