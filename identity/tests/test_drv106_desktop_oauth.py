"""DRV-106 regression tests — Drive Desktop OAuth profile + device registry.

Covers the server-bound acceptance boundary from DRV-104 HLD v2.5 §7:
  1. PKCE S256-only for the Drive Desktop client (plain/missing fails closed).
  2. Loopback redirect allowlist (127.0.0.1 / [::1], any ephemeral port).
  3. Refresh-family rotation: consumed token revoked, descendant carries family.
  4. Refresh-token replay revokes the WHOLE family (fail-closed invalid_grant).
  5. Device registry: register → heartbeat → revoke denies refresh.
  6. Revoke-all signs out every device family.
"""
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate

from identity import oauth_views
from identity.models import (
    IssuedRefreshToken,
    OAuthClient,
    OAuthDevice,
    RevokedToken,
)
from identity.oauth_views import (
    DRIVE_DESKTOP_CLIENT_ID,
    DeviceRegistryView,
    TokenView,
    _is_loopback_redirect,
    _mint_tokens,
    _revoke_refresh_family,
)

User = get_user_model()

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


def _make_drive_desktop_client():
    return OAuthClient.objects.create(
        client_id=DRIVE_DESKTOP_CLIENT_ID,
        client_name='Shizuha Drive for Desktop',
        redirect_uris=['http://127.0.0.1', 'http://[::1]'],
        grant_types=['authorization_code', 'refresh_token'],
        response_types=['code'],
        scope='drive:files.read drive:files.write profile',
        client_type=OAuthClient.CLIENT_TYPE_PUBLIC,
        is_system=True,
    )


class LoopbackRedirectTests(TestCase):
    def test_loopback_hosts_accepted(self):
        for uri in (
            'http://127.0.0.1:49152/callback',
            'http://127.0.0.1/callback',
            'http://[::1]:49152/callback',
            'http://[::1]/callback',
        ):
            self.assertTrue(_is_loopback_redirect(uri), uri)

    def test_non_loopback_rejected(self):
        for uri in (
            'http://localhost:49152/callback',
            'https://shizuha.com/callback',
            'http://192.168.1.10:49152/callback',
            'http://example.com/callback',
            'custom-scheme://callback',
        ):
            self.assertFalse(_is_loopback_redirect(uri), uri)


class DriveDesktopAuthorizeEnforcementTests(TestCase):
    def setUp(self):
        self.client_obj = _make_drive_desktop_client()
        self.user = User.objects.create_user(
            username='drv106', email='drv106@example.com', password='x',
        )

    def _validate(self, **overrides):
        params = {
            'client_id': DRIVE_DESKTOP_CLIENT_ID,
            'redirect_uri': 'http://127.0.0.1:49152/callback',
            'response_type': 'code',
            'code_challenge': 'a' * 43,
            'code_challenge_method': 'S256',
        }
        params.update(overrides)
        return oauth_views._validate_authorize_params(params)

    def test_s256_accepted(self):
        client, err, params = self._validate()
        self.assertIsNone(err)
        self.assertEqual(params['code_challenge_method'], 'S256')

    def test_plain_pkce_rejected_for_drive_desktop(self):
        _, err, _ = self._validate(code_challenge_method='plain')
        self.assertIsNotNone(err)
        self.assertIn('S256', err['error_description'])

    def test_missing_code_challenge_rejected(self):
        _, err, _ = self._validate(code_challenge='')
        self.assertIsNotNone(err)

    def test_non_loopback_redirect_rejected(self):
        # A non-loopback redirect fails closed — either at the client's
        # redirect_uri_allowed allowlist (only loopback URIs registered) or at
        # the DRV-106 loopback check.
        _, err, _ = self._validate(
            redirect_uri='https://shizuha.com/callback',
        )
        self.assertIsNotNone(err)
        self.assertIn('redirect', err['error_description'])


class RefreshFamilyRotationTests(TestCase):
    def setUp(self):
        self.client_obj = _make_drive_desktop_client()
        self.user = User.objects.create_user(
            username='drv106r', email='drv106r@example.com', password='x',
        )
        self.factory = APIRequestFactory()
        self.device = OAuthDevice.objects.create(
            user=self.user, device_id='dev-1', client=self.client_obj,
            name='Test PC', os='Windows', build='1.0.0',
            last_seen_at=timezone.now(),
        )

    def _mint(self, family='fam-1', device=None):
        return _mint_tokens(
            self.user, self.client_obj, self.client_obj.scope,
            'https://id.example', user_agent='test',
            token_family=family, device=device,
        )

    def _refresh(self, refresh_token, client_id=DRIVE_DESKTOP_CLIENT_ID):
        req = self.factory.post(
            '/api/oauth/token/',
            {'grant_type': 'refresh_token', 'refresh_token': refresh_token,
             'client_id': client_id},
            format='json',
        )
        return TokenView.as_view()(req)

    def test_rotation_revokes_consumed_token_and_carries_family(self):
        tokens = self._mint(family='fam-rot', device=self.device)
        r1 = tokens['refresh_token']
        resp = self._refresh(r1)
        self.assertEqual(resp.status_code, 200)
        r2 = resp.data['refresh_token']
        # Consumed token is revoked.
        self.assertTrue(
            IssuedRefreshToken.objects.filter(
                jti=oauth_views._decode_oauth_refresh_token(r1)['jti'],
                revoked_at__isnull=False,
            ).exists()
        )
        # Descendant carries the same family.
        self.assertEqual(
            oauth_views._decode_oauth_refresh_token(r2)['token_family'], 'fam-rot',
        )

    def test_replay_of_consumed_token_revokes_family(self):
        tokens = self._mint(family='fam-replay', device=self.device)
        r1 = tokens['refresh_token']
        self.assertEqual(self._refresh(r1).status_code, 200)
        # Replay the consumed token → invalid_grant + family revoked.
        resp = self._refresh(r1)
        self.assertEqual(resp.status_code, 400)
        # No active descendants remain.
        self.assertFalse(
            IssuedRefreshToken.objects.filter(
                user=self.user, client=self.client_obj,
                token_family='fam-replay', revoked_at__isnull=True,
            ).exists()
        )

    def test_revoked_device_cannot_refresh(self):
        tokens = self._mint(family='fam-dev', device=self.device)
        self.device.is_active = False
        self.device.revoked_at = timezone.now()
        self.device.save(update_fields=['is_active', 'revoked_at'])
        resp = self._refresh(tokens['refresh_token'])
        self.assertEqual(resp.status_code, 400)
        self.assertIn('device revoked', resp.data['error_description'])

    def test_revoke_family_marks_device_inactive(self):
        self._mint(family='fam-x', device=self.device)
        _revoke_refresh_family(
            user=self.user, client=self.client_obj,
            token_family='fam-x', reason='test',
        )
        self.device.refresh_from_db()
        self.assertFalse(self.device.is_active)


class DeviceRegistryViewTests(TestCase):
    def setUp(self):
        self.client_obj = _make_drive_desktop_client()
        self.user = User.objects.create_user(
            username='drv106d', email='drv106d@example.com', password='x',
        )
        self.factory = APIRequestFactory()
        self.device = OAuthDevice.objects.create(
            user=self.user, device_id='dev-a', client=self.client_obj,
            name='PC A', os='Windows', build='1.0.0',
            last_seen_at=timezone.now(),
        )

    def _call(self, action, **data):
        req = self.factory.post('/api/oauth/devices/', {'action': action, **data}, format='json')
        force_authenticate(req, user=self.user)
        return DeviceRegistryView.as_view()(req)

    def test_register_creates_and_heartbeats(self):
        resp = self._call('register', device_id='dev-new', device_name='Laptop')
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.data['registered'])
        dev = OAuthDevice.objects.get(user=self.user, device_id='dev-new')
        self.assertEqual(dev.name, 'Laptop')

    def test_revoke_device_denies_family(self):
        tokens = _mint_tokens(
            self.user, self.client_obj, self.client_obj.scope,
            'https://id.example', token_family='fam-d', device=self.device,
        )
        resp = self._call('revoke', device_id='dev-a')
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.data['revoked'])
        # Refresh now fails (device revoked + family revoked).
        req = self.factory.post(
            '/api/oauth/token/',
            {'grant_type': 'refresh_token',
             'refresh_token': tokens['refresh_token'],
             'client_id': DRIVE_DESKTOP_CLIENT_ID},
            format='json',
        )
        refresh_resp = TokenView.as_view()(req)
        self.assertEqual(refresh_resp.status_code, 400)

    def test_revoke_all_signs_out_every_device(self):
        dev2 = OAuthDevice.objects.create(
            user=self.user, device_id='dev-b', client=self.client_obj,
            name='PC B', os='Windows', build='1.0.0',
            last_seen_at=timezone.now(),
        )
        _mint_tokens(
            self.user, self.client_obj, self.client_obj.scope,
            'https://id.example', token_family='fam-1', device=self.device,
        )
        _mint_tokens(
            self.user, self.client_obj, self.client_obj.scope,
            'https://id.example', token_family='fam-2', device=dev2,
        )
        resp = self._call('revoke-all')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data['revoked_devices'], 2)
        self.assertFalse(
            OAuthDevice.objects.filter(user=self.user, is_active=True).exists()
        )
        self.assertFalse(
            IssuedRefreshToken.objects.filter(
                user=self.user, client=self.client_obj, revoked_at__isnull=True,
            ).exists()
        )

    def test_revoke_all_exclude_current_keeps_current_device(self):
        dev2 = OAuthDevice.objects.create(
            user=self.user, device_id='dev-b', client=self.client_obj,
            name='PC B', os='Windows', build='1.0.0',
            last_seen_at=timezone.now(),
        )
        resp = self._call('revoke-all', exclude_current=True, device_id='dev-a')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data['revoked_devices'], 1)
        self.device.refresh_from_db()
        dev2.refresh_from_db()
        self.assertTrue(self.device.is_active)
        self.assertFalse(dev2.is_active)


class DriveDesktopAudienceTests(TestCase):
    """DRV-106 §7 audience contract: Drive-resource audience, not client id."""

    def setUp(self):
        self.client_obj = _make_drive_desktop_client()
        self.user = User.objects.create_user(
            username='drv106a', email='drv106a@example.com', password='x',
        )

    def test_access_token_carries_drive_resource_audience(self):
        tokens = _mint_tokens(
            self.user, self.client_obj, self.client_obj.scope,
            'https://id.example',
        )
        access = oauth_views._decode_oauth_access_token_for_status(
            tokens['access_token'],
        )
        self.assertEqual(access['aud'], ['drive'])
        # Distinct from the OAuth client id and the OIDC ID-token audience.
        self.assertNotEqual(access['aud'], [self.client_obj.client_id])
        refresh = oauth_views._decode_oauth_refresh_token(
            tokens['refresh_token'],
        )
        self.assertNotEqual(refresh.get('aud'), ['drive'])

    def test_non_drive_client_keeps_scope_audience(self):
        other = OAuthClient.objects.create(
            client_id='other-client',
            client_name='Other',
            redirect_uris=['http://127.0.0.1'],
            grant_types=['authorization_code', 'refresh_token'],
            response_types=['code'],
            scope='openid profile',
            client_type=OAuthClient.CLIENT_TYPE_PUBLIC,
        )
        tokens = _mint_tokens(
            self.user, other, other.scope, 'https://id.example',
        )
        access = oauth_views._decode_oauth_access_token_for_status(
            tokens['access_token'],
        )
        self.assertNotEqual(access['aud'], ['drive'])
