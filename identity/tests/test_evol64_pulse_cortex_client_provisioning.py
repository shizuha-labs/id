"""EVOL-64: Pulse -> Cortex cost aggregator client provisioning + token shape.

Proves at the ID boundary the exact contract the Cortex M2M scope gate (cortex
PR #84) and the Pulse token-exchange mint require:
  * a confidential, client_credentials-only, no-wildcard client
    (scope 'cortex:usage-by-user.read') is provisioned idempotently from the
    secret verifier env;
  * the client_credentials grant mints an RS256, <=15m, is_service token with
    scope 'cortex:usage-by-user.read' and aud ['cortex'] (derived from the
    scope <service>: prefix), carrying NO user claims and NO staff claims.
"""
import hashlib
import os
from io import StringIO
from unittest import mock

import jwt as pyjwt
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from rest_framework.test import APIRequestFactory

from identity import oauth_views
from identity.models import OAuthClient
from identity.oauth_views import TokenView

CLIENT_ID = 'pulse-cortex-cost'
SCOPE = 'cortex:usage-by-user.read'
SECRET = 'evol64-test-secret-for-pulse-cortex-cost-0123456789abcdef'
VERIFIER = hashlib.sha256(SECRET.encode()).hexdigest()


class Evol64PulseCortexClientProvisioningTests(TestCase):
    def _env(self, **over):
        base = {
            'PULSE_CORTEX_OAUTH_CLIENT_SECRET': '',
            'PULSE_CORTEX_OAUTH_CLIENT_SECRET_SHA256': VERIFIER,
        }
        base.update(over)
        return mock.patch.dict(os.environ, base)

    def _provision(self, **env):
        output = StringIO()
        with self._env(**env):
            call_command('upsert_pulse_cortex_cost_client', stdout=output)
        return output

    def _provisioned(self):
        return OAuthClient.objects.get(client_id=CLIENT_ID)

    def test_provisions_confidential_scoped_client(self):
        self._provision()
        client = self._provisioned()
        self.assertEqual(client.scope, SCOPE)
        self.assertEqual(client.grant_types, ['client_credentials'])
        self.assertEqual(client.client_type, OAuthClient.CLIENT_TYPE_CONFIDENTIAL)
        self.assertTrue(client.is_system)
        self.assertEqual(client.client_secret_hash, VERIFIER)
        self.assertEqual(client.response_types, [])

    def test_provisioning_is_idempotent(self):
        self._provision()
        self._provision()
        self.assertEqual(OAuthClient.objects.filter(client_id=CLIENT_ID).count(), 1)

    def test_missing_verifier_fails_closed(self):
        with self._env(PULSE_CORTEX_OAUTH_CLIENT_SECRET_SHA256=''), \
             self.assertRaisesRegex(CommandError, 'has no verifier'):
            call_command('upsert_pulse_cortex_cost_client')

    def test_later_secret_recovers_and_preserves_valid_hash(self):
        output = StringIO()
        with self._env(PULSE_CORTEX_OAUTH_CLIENT_SECRET_SHA256=''):
            with self.assertRaisesRegex(CommandError, 'has no verifier'):
                call_command('upsert_pulse_cortex_cost_client', stdout=output)
        self.assertFalse(
            OAuthClient.objects.filter(client_id=CLIENT_ID).exists()
        )

        # A later restart with the verifier provisions; another without either
        # secret env preserves the valid hash (restart-safe semantics).
        self._provision()
        with self._env(PULSE_CORTEX_OAUTH_CLIENT_SECRET_SHA256=''):
            call_command('upsert_pulse_cortex_cost_client')
        self._provisioned().refresh_from_db()
        self.assertEqual(self._provisioned().client_secret_hash, VERIFIER)

    def test_client_credentials_mints_expected_service_token_shape(self):
        """The exact token request shape (grant, secret, scope) yields the
        RS256/service claims the Cortex gate authorizes — aud derived from the
        scope <service> prefix, no user/staff claims, <=15m TTL."""
        self._provision()
        request = APIRequestFactory().post(
            '/id/api/oauth/token',
            {
                'grant_type': 'client_credentials',
                'client_id': CLIENT_ID,
                'client_secret': SECRET,
                'scope': SCOPE,
            },
            format='json',
        )
        response = TokenView.as_view()(request)
        self.assertEqual(response.status_code, 200, response.data)
        access = response.data['access_token']
        self.assertEqual(pyjwt.get_unverified_header(access)['alg'], 'RS256')

        claims = pyjwt.decode(access, options={'verify_signature': False})
        self.assertTrue(claims['is_service'])
        self.assertEqual(claims['sub'], f'service:{CLIENT_ID}')
        self.assertEqual(claims['scope'], SCOPE)
        self.assertEqual(claims['aud'], ['cortex'])  # <service> prefix of the scope
        self.assertEqual(claims['client_id'], CLIENT_ID)
        self.assertLessEqual(claims['exp'] - claims['iat'], 15 * 60)
        # service identity: no user claims, no synthetic staff/superuser.
        self.assertNotIn('user_id', claims)
        self.assertFalse(claims.get('is_staff', False))
        self.assertFalse(claims.get('is_superuser', False))
        self.assertNotIn('refresh_token', response.data)

    def test_token_payload_captured_at_mint_is_exact(self):
        """Structural proof of the payload WITHOUT the RSA sealing step (mirrors
        the books provisioning test): aud=['cortex'], is_service, no user_id."""
        self._provision()
        captured = {}
        request = APIRequestFactory().post(
            '/id/api/oauth/token',
            {
                'grant_type': 'client_credentials',
                'client_id': CLIENT_ID,
                'client_secret': SECRET,
                'scope': SCOPE,
            },
            format='json',
        )
        with mock.patch.object(
            oauth_views, '_rs256_encode',
            side_effect=lambda payload: captured.update(payload) or 'signed-token',
        ):
            response = TokenView.as_view()(request)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(captured['client_id'], CLIENT_ID)
        self.assertEqual(captured['scope'], SCOPE)
        self.assertEqual(captured['aud'], ['cortex'])
        self.assertTrue(captured['is_service'])
        self.assertNotIn('user_id', captured)
