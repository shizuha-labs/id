"""PLAT-356 — M2M (client_credentials) revocation via the existing cutoff + jti
mechanism (aoi arbitration 2026-06-20: there is no ``token_version`` in this
codebase; ``OAuthClient.access_revoked_before`` + ``RevokedToken`` IS the M2M
revocation path).

Proves end-to-end that a set ``OAuthClient.access_revoked_before`` BOTH:
  1. refuses to mint new client_credentials (M2M) tokens (kill-switch), AND
  2. revokes an already-issued M2M token — the ``/api/oauth/revocation-status``
     check that RS256-only resource servers call now reports it inactive.
"""
from contextlib import ExitStack
from datetime import datetime, timezone as _dt_timezone
import hashlib
import importlib
from io import StringIO
import os
from types import SimpleNamespace
from unittest import mock

from django.apps import apps as django_apps
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, TestCase
from django.utils import timezone
from rest_framework.test import APIRequestFactory

from identity import oauth_views
from identity.models import OAuthClient
from identity.oauth_views import OAuthRevocationStatusView, TokenView


class M2MClientCredentialsRevocationTests(SimpleTestCase):
    def setUp(self):
        self.factory = APIRequestFactory()

    def _conf_client(self, *, cutoff=None):
        # A confidential client registered for the client_credentials grant.
        return SimpleNamespace(
            client_id='svc-mail',
            client_type=OAuthClient.CLIENT_TYPE_CONFIDENTIAL,
            client_secret_hash='x' * 64,
            grant_types=['client_credentials'],
            scope='mail:send.read',
            access_revoked_before=cutoff,
        )

    def _mint(self, client, *, capture=None):
        req = self.factory.post(
            '/id/api/oauth/token',
            {'grant_type': 'client_credentials', 'client_id': client.client_id,
             'client_secret': 'secret', 'scope': 'mail:send.read'},
            format='json',
        )
        with ExitStack() as stack:
            # Bypass secret hashing — auth is exercised elsewhere; here we test the
            # cutoff/mint behaviour for an authenticated confidential client.
            stack.enter_context(mock.patch.object(
                oauth_views.TokenView, '_authenticate_client', return_value=(client, None)))
            if capture is not None:
                stack.enter_context(mock.patch.object(
                    oauth_views, '_rs256_encode', side_effect=capture))
            return TokenView.as_view()(req)

    def test_refuses_to_mint_when_client_cutoff_set(self):
        """A set access_revoked_before is the kill-switch: no new M2M tokens."""
        client = self._conf_client(cutoff=timezone.now())
        resp = self._mint(client)
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.data['error'], 'invalid_client')
        self.assertEqual(resp.data['error_description'], 'client revoked')


    def test_client_credentials_requires_explicit_non_empty_scope(self):
        """M2M requests must ask for the least-privilege scope they need;
        omitting scope must not silently mint every registered client scope."""
        client = self._conf_client(cutoff=None)
        req = self.factory.post(
            '/id/api/oauth/token',
            {'grant_type': 'client_credentials', 'client_id': client.client_id,
             'client_secret': 'secret'},
            format='json',
        )
        with mock.patch.object(
            oauth_views.TokenView, '_authenticate_client', return_value=(client, None)
        ), mock.patch.object(oauth_views, '_rs256_encode') as encode:
            resp = TokenView.as_view()(req)
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.data['error'], 'invalid_scope')
        self.assertIn('explicit non-empty', resp.data['error_description'])
        encode.assert_not_called()

    def test_client_credentials_rejects_blank_scope(self):
        client = self._conf_client(cutoff=None)
        req = self.factory.post(
            '/id/api/oauth/token',
            {'grant_type': 'client_credentials', 'client_id': client.client_id,
             'client_secret': 'secret', 'scope': '   '},
            format='json',
        )
        with mock.patch.object(
            oauth_views.TokenView, '_authenticate_client', return_value=(client, None)
        ), mock.patch.object(oauth_views, '_rs256_encode') as encode:
            resp = TokenView.as_view()(req)
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.data['error'], 'invalid_scope')
        encode.assert_not_called()

    def test_already_issued_m2m_token_revoked_by_cutoff_end_to_end(self):
        """Mint an M2M token, then revoke the client → the revocation-status
        endpoint resource servers call reports the existing token inactive, and
        further mints are refused."""
        client = self._conf_client(cutoff=None)
        captured = {}

        def _capture(payload):
            captured.update(payload)
            return 'signed-m2m-token'

        resp = self._mint(client, capture=_capture)
        self.assertEqual(resp.status_code, 200)
        # M2M token shape: service identity, carries client_id + iat + jti, never a user.
        self.assertTrue(captured.get('is_service'))
        self.assertEqual(captured['client_id'], client.client_id)
        self.assertNotIn('user_id', captured)
        self.assertIn('iat', captured)
        self.assertIn('jti', captured)

        # Emergency-revoke the client AFTER issuance: cutoff strictly after token iat.
        client.access_revoked_before = datetime.fromtimestamp(
            int(captured['iat']) + 1, tz=_dt_timezone.utc)

        # The /api/oauth/revocation-status check (RS256-only resource servers call
        # this) must now report the already-issued token inactive. Real cutoff
        # comparison runs; only the agent-cutoff DB lookup is stubbed to None
        # (this is a client-wide revocation).
        status_req = self.factory.post(
            '/id/api/oauth/revocation-status', {'token': 'signed-m2m-token'}, format='json')
        with mock.patch.object(oauth_views, '_decode_oauth_access_token_for_status',
                               return_value=dict(captured)), \
             mock.patch.object(oauth_views, '_agent_cutoff_for_token', return_value=None), \
             mock.patch.object(OAuthClient.objects, 'get', return_value=client):
            status_resp = OAuthRevocationStatusView.as_view()(status_req)
        self.assertEqual(status_resp.status_code, 200)
        # PLAT-5996: the revocation-status response now also carries the
        # subject's current token_version (0 for a client token) alongside
        # `active` — consumers compare the version to reject replayed
        # pre-revocation tokens.
        self.assertEqual(status_resp.data, {'active': False, 'token_version': 0})

        # ...and no new token can be minted while the cutoff stands.
        refuse = self._mint(client)
        self.assertEqual(refuse.status_code, 400)
        self.assertEqual(refuse.data['error_description'], 'client revoked')


class CortexBooksClientProvisioningTests(TestCase):
    def _without_secret_env(self):
        return mock.patch.dict(os.environ, {
            'CORTEX_BOOKS_OAUTH_CLIENT_SECRET': '',
            'CORTEX_BOOKS_OAUTH_CLIENT_SECRET_SHA256': '',
        })

    def test_absent_secret_then_later_secret_recovers_and_mints_exact_scope(self):
        # The one-shot migration can run before deploy#380 mounts the verifier.
        # It must not leave a permanently secretless confidential client.
        migration = importlib.import_module(
            'identity.migrations.0033_seed_cortex_books_payout_client'
        )
        with self._without_secret_env():
            migration.seed_client(django_apps, None)
        self.assertFalse(OAuthClient.objects.filter(client_id='cortex-books-payouts').exists())

        # The restart-safe command also fails loudly until the verifier exists.
        with self._without_secret_env(), self.assertRaisesRegex(CommandError, 'has no verifier'):
            call_command('upsert_cortex_books_payout_client')

        raw_secret = 'later-provisioned-test-secret'
        output = StringIO()
        with mock.patch.dict(os.environ, {
            'CORTEX_BOOKS_OAUTH_CLIENT_SECRET': raw_secret,
            'CORTEX_BOOKS_OAUTH_CLIENT_SECRET_SHA256': '',
        }):
            call_command('upsert_cortex_books_payout_client', stdout=output)
        client = OAuthClient.objects.get(client_id='cortex-books-payouts')
        self.assertEqual(client.client_secret_hash, hashlib.sha256(raw_secret.encode()).hexdigest())
        self.assertIn('secret_hash_configured=True', output.getvalue())

        captured = {}
        request = APIRequestFactory().post(
            '/id/api/oauth/token',
            {
                'grant_type': 'client_credentials',
                'client_id': 'cortex-books-payouts',
                'client_secret': raw_secret,
                'scope': 'books:cortex-provider-payable.create',
            },
            format='json',
        )
        with mock.patch.object(
            oauth_views, '_rs256_encode',
            side_effect=lambda payload: captured.update(payload) or 'signed-token',
        ):
            response = TokenView.as_view()(request)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(captured['client_id'], 'cortex-books-payouts')
        self.assertEqual(captured['scope'], 'books:cortex-provider-payable.create')
        self.assertEqual(captured['aud'], ['books'])
        self.assertTrue(captured['is_service'])
        self.assertNotIn('user_id', captured)

        # A later restart without either secret env preserves the valid hash.
        with self._without_secret_env():
            call_command('upsert_cortex_books_payout_client')
        client.refresh_from_db()
        self.assertEqual(client.client_secret_hash, hashlib.sha256(raw_secret.encode()).hexdigest())

    def test_migration_never_seeds_malformed_configured_hash(self):
        migration = importlib.import_module(
            'identity.migrations.0033_seed_cortex_books_payout_client'
        )
        with mock.patch.dict(os.environ, {
            'CORTEX_BOOKS_OAUTH_CLIENT_SECRET': '',
            'CORTEX_BOOKS_OAUTH_CLIENT_SECRET_SHA256': 'not-a-sha256-digest',
        }):
            migration.seed_client(django_apps, None)
        self.assertFalse(
            OAuthClient.objects.filter(client_id='cortex-books-payouts').exists()
        )

    def test_upsert_rejects_malformed_preexisting_hash_without_claiming_success(self):
        client = OAuthClient.objects.create(
            client_id='cortex-books-payouts',
            client_secret_hash='partial-verifier',
            client_name='Cortex Books Provider Payouts',
            grant_types=['client_credentials'],
            scope='books:cortex-provider-payable.create',
            client_type=OAuthClient.CLIENT_TYPE_CONFIDENTIAL,
            is_system=True,
        )
        output = StringIO()
        with self._without_secret_env(), self.assertRaisesRegex(
            CommandError, 'existing cortex-books-payouts verifier must be a 64-character'
        ):
            call_command('upsert_cortex_books_payout_client', stdout=output)
        client.refresh_from_db()
        self.assertEqual(client.client_secret_hash, 'partial-verifier')
        self.assertNotIn('secret_hash_configured=True', output.getvalue())
