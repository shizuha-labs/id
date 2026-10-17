import asyncio
import importlib.util
import json
import sys
import types
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import jwt
from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate
from rest_framework_simplejwt.exceptions import AuthenticationFailed

from identity import oauth_views
from identity.authentication import OAuthClientRevocationJWTAuthentication
from identity.models import (
    IssuedRefreshToken,
    OAuthClient,
    OAuthClientAgentRevocationCutoff,
    RevokedToken,
)
from identity.oauth_views import (
    OAuthRevocationStatusView,
    RevokeView,
    TokenView,
    _mint_tokens,
    _oauth_token_precedes_client_cutoff,
)

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


def _load_mcp_base_module():
    repo_root = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location(
        'shizuha_mcp_base_for_tests',
        repo_root / 'mcp-server' / 'base.py',
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@contextmanager
def _mcp_access_token_stub():
    provider = types.ModuleType('mcp.server.auth.provider')

    class AccessToken(SimpleNamespace):
        pass

    provider.AccessToken = AccessToken
    modules = {
        'mcp': types.ModuleType('mcp'),
        'mcp.server': types.ModuleType('mcp.server'),
        'mcp.server.auth': types.ModuleType('mcp.server.auth'),
        'mcp.server.auth.provider': provider,
    }
    with mock.patch.dict(sys.modules, modules):
        yield AccessToken


class _User(SimpleNamespace):
    is_authenticated = True
    is_staff = False
    is_superuser = False
    email = 'actor@shizuha.com'
    username = 'actor'
    id = 1


class ClientIdRevokeViewTests(SimpleTestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.view = RevokeView.as_view()

    def _post(self, data, *, user=None, token=None):
        req = self.factory.post('/id/api/oauth/revoke', data, format='json')
        if user is not None:
            force_authenticate(req, user=user, token=token)
        return self.view(req)

    def _client(self, *, owner_id=99):
        return SimpleNamespace(
            client_id='mcp-auth-proxy',
            owner_id=owner_id,
            access_revoked_before=None,
            save=mock.Mock(),
        )

    def test_client_id_revoke_requires_authenticated_actor(self):
        resp = self._post({'client_id': 'mcp-auth-proxy'})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.data['error'], 'not_authenticated')

    def test_unknown_client_returns_404(self):
        with mock.patch.object(OAuthClient.objects, 'get', side_effect=OAuthClient.DoesNotExist):
            resp = self._post({'client_id': 'missing'}, user=_User())
        self.assertEqual(resp.status_code, 404)

    def test_cross_client_revoke_rejected_without_admin_or_self_claim(self):
        client = self._client(owner_id=2)
        with mock.patch.object(OAuthClient.objects, 'get', return_value=client):
            resp = self._post({'client_id': client.client_id}, user=_User(id=1))
        self.assertEqual(resp.status_code, 403)

    def test_admin_scoped_token_revokes_refresh_tokens_cuts_access_and_audits(self):
        client = self._client(owner_id=99)
        user = _User(id=1, email='svc-admin@shizuha.com')
        token = {'oauth_client_revoke': True}
        with mock.patch.object(OAuthClient.objects, 'get', return_value=client), \
             mock.patch.object(oauth_views, '_revoke_refresh_tokens_for_client', return_value=3) as revoke, \
             mock.patch.object(oauth_views, 'emit_oauth_client_revocation') as audit:
            resp = self._post(
                {'client_id': client.client_id, 'reason': 'compromise-drill'},
                user=user,
                token=token,
            )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data['revoked_tokens'], 3)
        self.assertIn('revoked_at', resp.data)
        self.assertIsNotNone(client.access_revoked_before)
        client.save.assert_called_once_with(update_fields=['access_revoked_before'])
        revoke.assert_called_once()
        _, kwargs = audit.call_args
        self.assertEqual(kwargs['revoked_client_id'], client.client_id)
        self.assertIsNone(kwargs['revoked_agent_id'])
        self.assertEqual(kwargs['revoker_identity'], 'svc-admin@shizuha.com')
        self.assertEqual(kwargs['reason'], 'compromise-drill')
        self.assertEqual(kwargs['revoked_tokens'], 3)

    def test_agent_scoped_revoke_uses_agent_cutoff_not_client_wide_cutoff(self):
        client = self._client(owner_id=99)
        user = _User(id=1, email='svc-admin@shizuha.com')
        token = {'oauth_client_revoke': True}
        with mock.patch.object(OAuthClient.objects, 'get', return_value=client), \
             mock.patch.object(oauth_views, '_revoke_refresh_tokens_for_client', return_value=1), \
             mock.patch.object(oauth_views, 'emit_oauth_client_revocation'), \
             mock.patch.object(
                 oauth_views.OAuthClientAgentRevocationCutoff.objects, 'update_or_create'
             ) as upsert:
            resp = self._post(
                {'client_id': client.client_id, 'agent_id': 'ryo', 'reason': 'agent-drill'},
                user=user,
                token=token,
            )

        self.assertEqual(resp.status_code, 200)
        client.save.assert_not_called()
        upsert.assert_called_once()
        _, kwargs = upsert.call_args
        self.assertEqual(kwargs['client'], client)
        self.assertEqual(kwargs['agent_id'], 'ryo')
        self.assertIn('access_revoked_before', kwargs['defaults'])

    def test_agent_scoped_revoke_rejects_overlong_agent_id_before_cutoff_write(self):
        client = self._client(owner_id=99)
        user = _User(id=1, email='svc-admin@shizuha.com')
        token = {'oauth_client_revoke': True}
        overlong_agent_id = 'a' * 151
        with mock.patch.object(OAuthClient.objects, 'get', return_value=client), \
             mock.patch.object(oauth_views, '_revoke_refresh_tokens_for_client') as revoke, \
             mock.patch.object(
                 oauth_views.OAuthClientAgentRevocationCutoff.objects, 'update_or_create'
             ) as upsert:
            resp = self._post(
                {'client_id': client.client_id, 'agent_id': overlong_agent_id},
                user=user,
                token=token,
            )

        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.data['error'], 'invalid_request')
        upsert.assert_not_called()
        revoke.assert_not_called()
        client.save.assert_not_called()

    def test_owner_without_admin_scope_or_self_token_is_forbidden(self):
        client = self._client(owner_id=1)
        with mock.patch.object(OAuthClient.objects, 'get', return_value=client):
            resp = self._post({'client_id': client.client_id}, user=_User(id=1))
        self.assertEqual(resp.status_code, 403)

    def test_enabled_services_admin_does_not_authorize_cross_client_revoke(self):
        client = self._client(owner_id=99)
        token = {'enabled_services': ['admin']}
        with mock.patch.object(OAuthClient.objects, 'get', return_value=client):
            resp = self._post({'client_id': client.client_id}, user=_User(id=1), token=token)
        self.assertEqual(resp.status_code, 403)

    def test_staff_user_can_revoke_cross_client(self):
        client = self._client(owner_id=99)
        user = _User(id=1, is_staff=True)
        with mock.patch.object(OAuthClient.objects, 'get', return_value=client), \
             mock.patch.object(oauth_views, '_revoke_refresh_tokens_for_client', return_value=0), \
             mock.patch.object(oauth_views, 'emit_oauth_client_revocation'):
            resp = self._post({'client_id': client.client_id}, user=user)
        self.assertEqual(resp.status_code, 200)

    def test_oauth_client_self_claim_can_revoke_itself(self):
        client = self._client(owner_id=99)
        user = _User(id=1)
        token = {'client_id': client.client_id}
        with mock.patch.object(OAuthClient.objects, 'get', return_value=client), \
             mock.patch.object(oauth_views, '_revoke_refresh_tokens_for_client', return_value=0), \
             mock.patch.object(oauth_views, 'emit_oauth_client_revocation'):
            resp = self._post({'client_id': client.client_id}, user=user, token=token)
        self.assertEqual(resp.status_code, 200)

    def test_token_revocation_with_client_id_preserves_rfc7009_public_path(self):
        token = {'jti': 'refresh-jti', 'user_id': 42, 'client_id': 'mcp-auth-proxy'}
        user = _User(id=42, email='agent@shizuha.com')
        client = self._client()

        with mock.patch.object(RevokeView, '_revoke_by_client_id') as emergency_revoke, \
             mock.patch.object(
                 oauth_views, '_decode_oauth_token_for_revocation', return_value=token,
             ), \
             mock.patch.object(oauth_views.User.objects, 'get', return_value=user), \
             mock.patch.object(OAuthClient.objects, 'get', return_value=client), \
             mock.patch.object(oauth_views.IssuedRefreshToken.objects, 'filter') as issued, \
             mock.patch.object(oauth_views.RevokedToken.objects, 'get_or_create') as revoke:
            resp = self._post({'token': 'opaque-refresh', 'client_id': client.client_id})

        self.assertEqual(resp.status_code, 200)
        emergency_revoke.assert_not_called()
        revoke.assert_called_once()
        issued.return_value.update.assert_called_once()
        _, kwargs = revoke.call_args
        self.assertEqual(kwargs['jti'], 'refresh-jti')
        self.assertEqual(kwargs['defaults']['client'], client)


class RS256TokenRevocationTests(TestCase):
    """RFC7009 must revoke the exact RS256 refresh tokens ID currently mints."""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = get_user_model().objects.create_user(
            username='ctx428-revoke',
            email='ctx428-revoke@example.invalid',
            password='unused',
        )
        self.client = OAuthClient.objects.create(
            client_id='ctx428-cortex',
            client_name='CTX-428 Cortex',
            redirect_uris=['https://cortex.example.invalid/callback'],
            grant_types=['authorization_code', 'refresh_token'],
            response_types=['code'],
            scope='openid profile email',
            owner=self.user,
        )

    def test_minted_rs256_refresh_cannot_refresh_after_rfc7009_revoke(self):
        tokens = _mint_tokens(
            self.user,
            self.client,
            self.client.scope,
            'https://shizuha.com/id',
        )
        refresh = tokens['refresh_token']
        claims = jwt.decode(refresh, options={'verify_signature': False})
        issued = IssuedRefreshToken.objects.get(jti=claims['jti'])

        revoke_request = self.factory.post(
            '/id/api/oauth/revoke',
            {'token': refresh, 'token_type_hint': 'refresh_token'},
            format='json',
        )
        revoked = RevokeView.as_view()(revoke_request)

        self.assertEqual(revoked.status_code, 200)
        self.assertTrue(RevokedToken.objects.filter(
            jti=claims['jti'], token_type='refresh',
        ).exists())
        issued.refresh_from_db()
        self.assertIsNotNone(issued.revoked_at)

        refresh_request = self.factory.post(
            '/id/api/oauth/token',
            {
                'grant_type': 'refresh_token',
                'refresh_token': refresh,
                'client_id': self.client.client_id,
            },
            format='json',
        )
        refreshed = TokenView.as_view()(refresh_request)
        self.assertEqual(refreshed.status_code, 400)
        self.assertEqual(refreshed.data['error'], 'invalid_grant')
        self.assertEqual(refreshed.data['error_description'], 'token revoked')


class OAuthClientCutoffTests(SimpleTestCase):
    def test_helper_rejects_tokens_issued_before_cutoff(self):
        cutoff = timezone.now()
        old_iat = int(cutoff.timestamp()) - 5
        client = SimpleNamespace(access_revoked_before=cutoff)
        self.assertTrue(_oauth_token_precedes_client_cutoff({'iat': old_iat}, client))

    def test_helper_rejects_tokens_matching_agent_cutoff(self):
        cutoff = timezone.now()
        old_iat = int(cutoff.timestamp()) - 5
        client = SimpleNamespace(access_revoked_before=None)
        token = {'iat': old_iat, 'username': 'ryo', 'email': 'ryo@shizuha.com'}
        agent_cutoff = SimpleNamespace(access_revoked_before=cutoff)
        with mock.patch.object(OAuthClientAgentRevocationCutoff.objects, 'filter') as filter_:
            filter_.return_value.filter.return_value.order_by.return_value.first.return_value = agent_cutoff
            self.assertTrue(_oauth_token_precedes_client_cutoff(token, client))

    def test_authentication_rejects_oauth_access_token_before_cutoff(self):
        cutoff = timezone.now()
        token = {'client_id': 'mcp-auth-proxy', 'iat': int(cutoff.timestamp()) - 5}
        client = SimpleNamespace(access_revoked_before=cutoff)
        auth = OAuthClientRevocationJWTAuthentication()
        with mock.patch(
            'rest_framework_simplejwt.authentication.JWTAuthentication.get_validated_token',
            return_value=token,
        ), mock.patch.object(OAuthClient.objects, 'only') as only:
            only.return_value.get.return_value = client
            with self.assertRaises(AuthenticationFailed):
                auth.get_validated_token('raw')

    def test_authentication_rejects_oauth_access_token_matching_agent_cutoff(self):
        cutoff = timezone.now()
        token = {
            'client_id': 'mcp-auth-proxy',
            'iat': int(cutoff.timestamp()) - 5,
            'username': 'ryo',
        }
        client = SimpleNamespace(access_revoked_before=None)
        agent_cutoff = SimpleNamespace(access_revoked_before=cutoff)
        auth = OAuthClientRevocationJWTAuthentication()
        with mock.patch(
            'rest_framework_simplejwt.authentication.JWTAuthentication.get_validated_token',
            return_value=token,
        ), mock.patch.object(OAuthClient.objects, 'only') as only, \
             mock.patch.object(OAuthClientAgentRevocationCutoff.objects, 'filter') as filter_:
            only.return_value.get.return_value = client
            filter_.return_value.filter.return_value.order_by.return_value.first.return_value = agent_cutoff
            with self.assertRaises(AuthenticationFailed):
                auth.get_validated_token('raw')

    def test_authentication_ignores_non_oauth_tokens(self):
        auth = OAuthClientRevocationJWTAuthentication()
        with mock.patch(
            'rest_framework_simplejwt.authentication.JWTAuthentication.get_validated_token',
            return_value={'user_id': 1},
        ), mock.patch(
            'identity.authentication._user_access_cutoff', return_value=None,
        ), mock.patch.object(OAuthClient.objects, 'only') as only:
            self.assertEqual(auth.get_validated_token('raw'), {'user_id': 1})
            only.assert_not_called()


class OAuthRevocationStatusViewTests(SimpleTestCase):
    def test_status_endpoint_reports_inactive_when_cutoff_matches_token(self):
        request = APIRequestFactory().post(
            '/id/api/oauth/revocation-status',
            {'token': 'signed-oauth-access'},
            format='json',
        )
        client = SimpleNamespace(client_id='mcp-auth-proxy', access_revoked_before=timezone.now())
        payload = {'client_id': client.client_id, 'iat': int(timezone.now().timestamp()) - 5}

        with mock.patch.object(
            oauth_views,
            '_decode_oauth_access_token_for_status',
            return_value=payload,
        ), mock.patch.object(OAuthClient.objects, 'get', return_value=client), \
             mock.patch.object(oauth_views, '_oauth_token_precedes_client_cutoff', return_value=True):
            resp = OAuthRevocationStatusView.as_view()(request)

        self.assertEqual(resp.status_code, 200)
        # PLAT-5996: the status endpoint now also returns the subject's current
        # token_version (0 for client tokens) so consumers can reject stale
        # versions. The `active` verdict is unchanged.
        self.assertEqual(resp.data, {'active': False, 'token_version': 0})


class MCPVerifierRevocationTests(SimpleTestCase):
    def test_mcp_verifier_offloads_revocation_status_http_call(self):
        base = _load_mcp_base_module()
        verifier = base.ShizuhaTokenVerifier('pulse', 'http://id.example/id')
        verifier._decode = mock.Mock(return_value=({
            'client_id': 'mcp-auth-proxy',
            'exp': int(timezone.now().timestamp()) + 300,
        }, "valid"))

        async def fake_to_thread(func, *args, **kwargs):
            self.assertEqual(func, verifier._fetch_oauth_token_revoked)
            self.assertEqual(args, ('signed-oauth-access',))
            self.assertEqual(kwargs, {})
            return True

        with mock.patch.object(base.asyncio, 'to_thread', side_effect=fake_to_thread) as to_thread, \
             mock.patch.object(base.requests, 'post') as post:
            result = asyncio.run(verifier.verify_token('signed-oauth-access'))

        self.assertIsNone(result)
        to_thread.assert_called_once()
        post.assert_not_called()

    def test_mcp_verifier_rejects_pre_revoke_oauth_access_token(self):
        base = _load_mcp_base_module()
        verifier = base.ShizuhaTokenVerifier('pulse', 'http://id.example/id')
        verifier._decode = mock.Mock(return_value=({
            'client_id': 'mcp-auth-proxy',
            'username': 'ryo',
            'iat': int(timezone.now().timestamp()) - 5,
            'exp': int(timezone.now().timestamp()) + 300,
        }, "valid"))
        response = mock.Mock(status_code=200)
        response.json.return_value = {'active': False}

        with mock.patch.object(base.requests, 'post', return_value=response) as post:
            result = asyncio.run(verifier.verify_token('signed-oauth-access'))

        self.assertIsNone(result)
        post.assert_called_once_with(
            'http://id.example/id/api/oauth/revocation-status',
            json={'token': 'signed-oauth-access'},
            timeout=2,
        )

    def test_mcp_verifier_derives_revocation_url_and_timeout_from_env(self):
        base = _load_mcp_base_module()
        with mock.patch.dict(base.os.environ, {
            'SHIZUHA_MCP_OAUTH_REVOCATION_URL': '',
            'SHIZUHA_MCP_OAUTH_REVOCATION_TIMEOUT': '0.25',
        }, clear=False):
            verifier = base.ShizuhaTokenVerifier('pulse', 'http://id.example/id')
        self.assertEqual(verifier._revocation_status_url(), 'http://id.example/id/api/oauth/revocation-status')
        self.assertEqual(verifier._revocation_timeout, 0.25)

        with mock.patch.dict(base.os.environ, {
            'SHIZUHA_MCP_OAUTH_REVOCATION_URL': 'http://shizuha-id.svc/id/api/oauth/revocation-status/',
            'SHIZUHA_MCP_OAUTH_REVOCATION_TIMEOUT': '0.75',
        }, clear=False):
            verifier = base.ShizuhaTokenVerifier('pulse', 'http://public.example/id')
        self.assertEqual(verifier._revocation_status_url(), 'http://shizuha-id.svc/id/api/oauth/revocation-status')
        self.assertEqual(verifier._revocation_timeout, 0.75)

    def test_mcp_verifier_serves_stale_cached_revoked_verdict_when_check_unavailable(self):
        base = _load_mcp_base_module()
        verifier = base.ShizuhaTokenVerifier('pulse', 'http://id.example/id')
        cache_key = base.hashlib.sha256(b'signed-oauth-access').hexdigest()
        verifier._revocation_cache[cache_key] = (base.time.monotonic() - 1, True)

        with mock.patch.dict(base.os.environ, {
            'SHIZUHA_CONNECT_JWT_TOKEN': '',
            'SHIZUHA_CONNECT_TOKEN': '',
            'SHIZUHA_PULSE_JWT_TOKEN': '',
            'JWT_TOKEN': '',
        }, clear=False), mock.patch.object(
            base.requests,
            'post',
            side_effect=base.requests.exceptions.RequestException('revocation down'),
        ):
            result = asyncio.run(verifier._oauth_token_revoked('signed-oauth-access', {'client_id': 'mcp-auth-proxy'}))

        self.assertTrue(result)
        snapshot = verifier.revocation_health_snapshot()
        self.assertEqual(snapshot['state'], 'degraded')
        self.assertEqual(snapshot['counters']['unavailable'], 1)
        self.assertEqual(snapshot['counters']['serve_stale_hit'], 1)
        self.assertEqual(snapshot['counters']['revoked'], 1)

    def test_mcp_verifier_fails_open_without_cached_verdict_when_check_unavailable(self):
        base = _load_mcp_base_module()
        verifier = base.ShizuhaTokenVerifier('pulse', 'http://id.example/id')

        with mock.patch.dict(base.os.environ, {
            'SHIZUHA_CONNECT_JWT_TOKEN': '',
            'SHIZUHA_CONNECT_TOKEN': '',
            'SHIZUHA_PULSE_JWT_TOKEN': '',
            'JWT_TOKEN': '',
        }, clear=False), mock.patch.object(
            base.requests,
            'post',
            side_effect=base.requests.exceptions.RequestException('revocation down'),
        ):
            result = asyncio.run(verifier._oauth_token_revoked('signed-oauth-access', {'client_id': 'mcp-auth-proxy'}))

        self.assertFalse(result)
        snapshot = verifier.revocation_health_snapshot()
        self.assertEqual(snapshot['state'], 'degraded')
        self.assertEqual(snapshot['counters']['unavailable'], 1)
        self.assertEqual(snapshot['counters']['fail_open_no_cache'], 1)
        self.assertEqual(snapshot['counters']['not_revoked'], 1)

    def test_mcp_verifier_fail_loud_dms_owner_on_degradation_transition(self):
        base = _load_mcp_base_module()
        with mock.patch.dict(base.os.environ, {
            'SHIZUHA_CONNECT_URL': 'http://connect.local',
            'SHIZUHA_MCP_OAUTH_REVOCATION_ALERT_RECIPIENT': 'ichi',
            'JWT_TOKEN': 'agent-token',
        }, clear=False):
            verifier = base.ShizuhaTokenVerifier('pulse', 'http://id.example/id')

        dm_response = mock.Mock(status_code=200)
        with mock.patch.dict(base.os.environ, {
            'SHIZUHA_CONNECT_URL': 'http://connect.local',
            'SHIZUHA_MCP_OAUTH_REVOCATION_ALERT_RECIPIENT': 'ichi',
            'JWT_TOKEN': 'agent-token',
        }, clear=False), mock.patch.object(
            base.requests,
            'post',
            side_effect=[base.requests.exceptions.RequestException('revocation down'), dm_response],
        ) as post:
            result = asyncio.run(verifier._oauth_token_revoked('signed-oauth-access', {'client_id': 'mcp-auth-proxy'}))

        self.assertFalse(result)
        self.assertEqual(post.call_count, 2)
        dm_call = post.call_args_list[1]
        self.assertEqual(dm_call.args[0], 'http://connect.local/api/messaging/dm/')
        self.assertEqual(dm_call.kwargs['json']['recipient_username'], 'ichi')
        self.assertIn('OAuth revocation checker degraded', dm_call.kwargs['json']['content'])
        self.assertIn('Owner: DevOps/ichi', dm_call.kwargs['json']['content'])
        self.assertEqual(dm_call.kwargs['headers']['Authorization'], 'Bearer agent-token')
        self.assertEqual(verifier.revocation_health_snapshot()['counters']['alert_sent'], 1)

    def test_mcp_verifier_health_route_exposes_non_sensitive_counters(self):
        base = _load_mcp_base_module()
        verifier = base.ShizuhaTokenVerifier('pulse', 'http://id.example/id')
        verifier._record_revocation_outcome('success')

        class FakeMCP:
            def __init__(self):
                self.routes = {}
                self._token_verifier = verifier

            def custom_route(self, path, methods):
                def decorator(func):
                    self.routes[path] = (methods, func)
                    return func
                return decorator

        mcp = FakeMCP()
        base._register_revocation_health_route(mcp)
        methods, handler = mcp.routes['/-/oauth-revocation-health']
        self.assertEqual(methods, ['GET'])

        response = asyncio.run(handler(None))
        body = json.loads(response.body.decode('utf-8'))
        self.assertEqual(body['state'], 'healthy')
        self.assertEqual(body['counters']['success'], 1)
        self.assertEqual(body['alert_recipient'], 'ichi')
        self.assertNotIn('token', json.dumps(body).lower())


    def test_mcp_verifier_rejects_m2m_audience_mismatch(self):
        base = _load_mcp_base_module()
        verifier = base.ShizuhaTokenVerifier('pulse', 'http://id.example/id')
        verifier._decode = mock.Mock(return_value=({
            'client_id': 'svc-mail',
            'sub': 'service:svc-mail',
            'is_service': True,
            'aud': ['mail'],
            'scope': 'mail:send.read',
            'exp': int(timezone.now().timestamp()) + 300,
        }, "valid"))

        with mock.patch.object(verifier, '_oauth_token_revoked', new=mock.AsyncMock(return_value=False)) as revoked:
            result = asyncio.run(verifier.verify_token('signed-m2m-access'))

        self.assertIsNone(result)
        revoked.assert_not_called()

    def test_mcp_verifier_accepts_matching_m2m_audience_and_scopes(self):
        base = _load_mcp_base_module()
        verifier = base.ShizuhaTokenVerifier('pulse', 'http://id.example/id')
        verifier._decode = mock.Mock(return_value=({
            'client_id': 'svc-pulse',
            'sub': 'service:svc-pulse',
            'is_service': True,
            'aud': ['pulse'],
            'scope': 'pulse:tasks.read pulse:tasks.write',
            'exp': int(timezone.now().timestamp()) + 300,
        }, "valid"))

        with (
            _mcp_access_token_stub(),
            mock.patch.object(verifier, '_oauth_token_revoked', new=mock.AsyncMock(return_value=False)),
        ):
            result = asyncio.run(verifier.verify_token('signed-m2m-access'))

        self.assertIsNotNone(result)
        self.assertEqual(result.client_id, 'svc-pulse')
        self.assertEqual(result.scopes, ['pulse:tasks.read', 'pulse:tasks.write'])

    def test_mcp_verifier_does_not_apply_m2m_audience_to_user_oauth_token(self):
        base = _load_mcp_base_module()
        verifier = base.ShizuhaTokenVerifier('pulse', 'http://id.example/id')
        verifier._decode = mock.Mock(return_value=({
            'client_id': 'web-client',
            'username': 'ryo',
            'aud': ['openid', 'profile', 'email'],
            'scope': 'openid profile email',
            'exp': int(timezone.now().timestamp()) + 300,
        }, "valid"))

        with (
            _mcp_access_token_stub(),
            mock.patch.object(verifier, '_oauth_token_revoked', new=mock.AsyncMock(return_value=False)) as revoked,
        ):
            result = asyncio.run(verifier.verify_token('signed-user-oauth-access'))

        self.assertIsNotNone(result)
        self.assertEqual(result.client_id, 'web-client')
        self.assertEqual(result.scopes, ['openid', 'profile', 'email'])
        revoked.assert_awaited_once()
