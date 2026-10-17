"""PLAT-356 (ren security finding #1) — public dynamic client registration (RFC
7591, AllowAny + no auth) must NOT let an anonymous caller self-provision a
machine-to-machine (client_credentials) client, which would let them mint RS256
service tokens. M2M/service clients are provisioned out-of-band.
"""
from unittest import mock

from django.test import SimpleTestCase
from rest_framework.test import APIRequestFactory

from identity import oauth_views
from identity.oauth_views import ClientRegistrationView


class DCRClientCredentialsGateTests(SimpleTestCase):
    def setUp(self):
        self.factory = APIRequestFactory()

    def _register(self, grant_types):
        req = self.factory.post('/id/api/oauth/register', {
            'client_name': 'x',
            'redirect_uris': ['https://example.test/cb'],
            'grant_types': grant_types,
            'token_endpoint_auth_method': 'client_secret_basic',
        }, format='json')
        return ClientRegistrationView.as_view()(req)

    def test_public_dcr_rejects_client_credentials(self):
        """A public caller cannot self-provision an M2M client — and no client row
        is created."""
        with mock.patch.object(oauth_views.OAuthClient.objects, 'create') as create:
            resp = self._register(['authorization_code', 'client_credentials'])
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.data['error'], 'invalid_client_metadata')
        create.assert_not_called()

    def test_public_dcr_allows_normal_grants(self):
        """Legitimate (non-M2M) dynamic registration still passes the gate."""
        fake = mock.Mock(client_id='c', client_name='x',
                         redirect_uris=['https://example.test/cb'],
                         grant_types=['authorization_code', 'refresh_token'],
                         response_types=['code'], scope='*')
        with mock.patch.object(oauth_views.OAuthClient.objects, 'create',
                               return_value=fake) as create:
            resp = self._register(['authorization_code', 'refresh_token'])
        create.assert_called_once()
        self.assertNotEqual(resp.status_code, 400)
