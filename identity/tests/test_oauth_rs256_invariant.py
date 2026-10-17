"""ID-61: OAuth minting is RS256-only for every supported grant."""
from unittest import mock

import jwt
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from identity.models import OAuthClient
from identity.oauth_rs256_invariant import (
    MembershipProjectionTemporarilyUnavailable,
    run_oauth_rs256_invariant_probe,
)
from identity.oauth_views import _mint_tokens

_projection_patcher = None


def setUpModule():
    global _projection_patcher
    _projection_patcher = mock.patch(
        'identity.oauth_views._fetch_membership_projection',
        return_value=({}, [], {}),
    )
    _projection_patcher.start()


def tearDownModule():
    _projection_patcher.stop()


class OAuthRS256InvariantTests(TestCase):
    def test_all_supported_grants_mint_rs256(self):
        result = run_oauth_rs256_invariant_probe()
        self.assertEqual(
            set(result),
            {'password', 'authorization_code', 'refresh_token', 'client_credentials'},
        )
        self.assertIn('refresh_token', result['password'])
        self.assertIn('id_token', result['authorization_code'])

    @mock.patch('identity.oauth_rs256_invariant.time.sleep')
    @mock.patch('identity.oauth_rs256_invariant._run_oauth_rs256_invariant_probe_once')
    def test_transient_membership_projection_failure_is_retried(
        self,
        run_once,
        sleep,
    ):
        expected = {'password': ['access_token']}
        run_once.side_effect = [
            MembershipProjectionTemporarilyUnavailable('password', retry_after=2),
            expected,
        ]

        self.assertEqual(run_oauth_rs256_invariant_probe(), expected)
        self.assertEqual(run_once.call_count, 2)
        sleep.assert_called_once_with(2)

    @mock.patch('identity.oauth_rs256_invariant.time.sleep')
    @mock.patch('identity.oauth_rs256_invariant._run_oauth_rs256_invariant_probe_once')
    def test_persistent_membership_projection_failure_still_fails(
        self,
        run_once,
        sleep,
    ):
        run_once.side_effect = MembershipProjectionTemporarilyUnavailable('password')

        with self.assertRaises(MembershipProjectionTemporarilyUnavailable):
            run_oauth_rs256_invariant_probe(max_attempts=3)

        self.assertEqual(run_once.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_legacy_flag_cannot_restore_hs256_minting(self):
        user = get_user_model().objects.create_user(
            username='id61-flag-off', email='id61-flag-off@example.invalid', password='pw'
        )
        client = OAuthClient.objects.create(
            client_id='id61-flag-off', client_name='flag ignored',
            redirect_uris=[], grant_types=['password'], response_types=[],
            scope='openid', owner=user,
        )
        with mock.patch.dict('os.environ', {'SHIZUHA_OAUTH_RS256': 'false'}):
            tokens = _mint_tokens(user, client, 'openid', 'https://id.example.invalid')
        for field in ('access_token', 'refresh_token', 'id_token'):
            self.assertEqual(jwt.get_unverified_header(tokens[field])['alg'], 'RS256')

    def test_source_has_no_simplejwt_stringify_mint_path(self):
        # A structural backstop against reintroducing the exact CTX-452 branch.
        import inspect
        from identity import oauth_views

        source = inspect.getsource(oauth_views._mint_tokens)
        self.assertNotIn('str(access)', source)
        self.assertNotIn('str(refresh)', source)
        self.assertNotIn('RefreshToken.for_user', source)
        self.assertNotIn('use_rs256', source)

    def test_client_specific_access_ttl_bounds_offline_revocation_lag(self):
        user = get_user_model().objects.create_user(
            username='id-mail-short-ttl', email='id-mail-short-ttl@example.invalid',
            password='pw',
        )
        client = OAuthClient.objects.create(
            client_id='id-mail-short-ttl', client_name='mail offline verifier',
            redirect_uris=[], grant_types=['authorization_code'], response_types=['code'],
            scope='openid email mail', owner=user, access_token_ttl_minutes=1,
        )

        tokens = _mint_tokens(user, client, client.scope, 'https://id.example.invalid')
        claims = jwt.decode(tokens['access_token'], options={'verify_signature': False})

        self.assertEqual(tokens['expires_in'], 60)
        self.assertLessEqual(claims['exp'] - claims['iat'], 60)

    @override_settings(OAUTH_ONLINE_USERINFO_CLIENT_NAMES=frozenset({'shizuha-mail'}))
    def test_mail_access_token_requires_online_userinfo_identity_resolution(self):
        user = get_user_model().objects.create_user(
            username='id-mail-online', email='id-mail-online@shizuha.com', password='pw',
        )
        client = OAuthClient.objects.create(
            client_id='id-mail-online', client_name='shizuha-mail',
            redirect_uris=[], grant_types=['authorization_code'], response_types=['code'],
            scope='openid email mail', owner=user, access_token_ttl_minutes=1,
        )

        tokens = _mint_tokens(user, client, client.scope, 'https://id.example.invalid')
        access_claims = jwt.decode(tokens['access_token'], options={'verify_signature': False})
        id_claims = jwt.decode(tokens['id_token'], options={'verify_signature': False})
        refresh_claims = jwt.decode(tokens['refresh_token'], options={'verify_signature': False})

        self.assertNotIn('email', access_claims)
        self.assertEqual(id_claims['email'], user.email)
        self.assertEqual(refresh_claims['email'], user.email)
