"""
OAuth 2.0 authorization server for Shizuha ID.

Implements the subset of RFC 6749 + RFC 7636 (PKCE) + RFC 7591 (dynamic client
registration) + RFC 8414 (authorization server metadata) needed by Claude Code
and other MCP clients. Tokens are reused from the existing JWT infrastructure
so downstream services validate OAuth-issued tokens the same way they validate
login-issued ones.

Endpoints (mounted under /id/api/oauth/ and /id/api/.well-known/):
  GET  /.well-known/oauth-authorization-server  RFC 8414 metadata
  POST /oauth/register                           RFC 7591 dynamic client registration
  GET  /oauth/authorize/info                     Resolve + validate authorize params
  POST /oauth/authorize/approve                  Emit authorization code
  POST /oauth/token                              Exchange code/refresh for tokens
  GET  /oauth/userinfo                           OIDC-style user info
"""
import base64
import hashlib
import logging
import secrets
from datetime import timedelta
from urllib.parse import unquote_plus, urlencode, urlparse

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.utils import timezone
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from datetime import datetime, timezone as _dt_timezone
from .audit import emit_oauth_client_revocation
from .authentication import OAuthClientRevocationJWTAuthentication, RS256OAuthBearerAuthentication
from .models import (
    AuthorizationCode,
    IssuedRefreshToken,
    OAuthClient,
    OAuthClientAgentRevocationCutoff,
    OAuthDevice,
    RevokedToken,
    UserProfile,
)
from .oauth_keys import build_jwks, get_signing_material
from .services import get_default_new_user_tools
from .views import (
    _fetch_membership_projection,
    _is_agent_user,
    _populate_standard_claims,
)

logger = logging.getLogger(__name__)
User = get_user_model()

AUTH_CODE_TTL_SECONDS = 600  # 10 min — RFC 6749 §4.1.2 recommends <10 min
DEFAULT_ACCESS_TTL_MINUTES = 60
DEFAULT_REFRESH_TTL_DAYS = 30

# DRV-106: the Drive Desktop public client id (see
# identity/management/commands/upsert_drive_desktop_client.py). It enforces
# PKCE S256-only and a loopback redirect allowlist.
DRIVE_DESKTOP_CLIENT_ID = 'drive-desktop'
DRIVE_DESKTOP_LOOPBACK_HOSTS = ('127.0.0.1', '[::1]')
# The Drive resource audience that Drive accepts verbatim for its access
# tokens (DRV-104 HLD v2.5 §7 audience contract). Distinct from the OAuth
# client id and the OIDC ID-token audience.
DRIVE_RESOURCE_AUDIENCE = 'drive'


def _is_drive_desktop_client(client: OAuthClient) -> bool:
    """True for the pre-provisioned Drive Desktop public client (DRV-106)."""
    return client.client_id == DRIVE_DESKTOP_CLIENT_ID


def _is_loopback_redirect(redirect_uri: str) -> bool:
    """RFC 8252 loopback redirect: 127.0.0.1 or [::1] with any ephemeral port."""
    try:
        parsed = urlparse(redirect_uri)
    except ValueError:
        return False
    if parsed.scheme != 'http':
        return False
    host = (parsed.hostname or '').lower()
    if host in DRIVE_DESKTOP_LOOPBACK_HOSTS:
        return True
    # urlparse normalizes [::1] to hostname '::1'
    if host == '::1':
        return True
    return False


def _issuer_url(request) -> str:
    """Canonical OAuth issuer URL (public-facing)."""
    configured = getattr(settings, 'OAUTH_ISSUER_URL', '').rstrip('/')
    if configured:
        return configured
    return f"{request.scheme}://{request.get_host()}/id"


def _gen_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def _verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    if not code_verifier:
        return False
    if method == 'plain':
        return secrets.compare_digest(code_verifier, code_challenge)
    if method == 'S256':
        digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
        return secrets.compare_digest(expected, code_challenge)
    return False


def _populate_enabled_services(token, user):
    """Populate enabled_services claim via the canonical computation (INV-5 / ID-11)."""
    from .services import get_effective_services
    token['enabled_services'] = get_effective_services(user)


def _rs256_encode(payload: dict) -> str:
    """Sign a JWT payload with RS256 using the shizuha-id keypair."""
    import jwt as _jwt
    material = get_signing_material()
    return _jwt.encode(
        payload,
        material['private_pem'],
        algorithm='RS256',
        headers={'kid': material['kid']},
    )


def _decode_oauth_refresh_token(encoded: str):
    """Decode current RS256 refresh tokens; accept legacy HS256 only to upgrade.

    ID-61 removes every HS256 *mint* path. Existing OAuth sessions may still
    present an HS256 refresh token during the one-release rollback window, so
    accept it through SimpleJWT and immediately rotate it into RS256 tokens.
    """
    import jwt as _jwt

    try:
        alg = _jwt.get_unverified_header(encoded).get('alg')
    except Exception as exc:
        raise ValueError(f'invalid refresh-token header: {exc}') from exc
    if alg == 'RS256':
        payload = _jwt.decode(
            encoded,
            get_signing_material()['public_pem'],
            algorithms=['RS256'],
            options={'verify_aud': False},
        )
        if payload.get('token_type') != 'refresh':
            raise ValueError('token is not a refresh token')
        return payload
    if alg == 'HS256':
        return RefreshToken(encoded)
    raise ValueError(f'unsupported refresh-token alg {alg!r}')


def _decode_oauth_token_for_revocation(encoded: str, token_type: str):
    """Verify an OAuth token without assuming the project HS256 backend.

    OAuth grants are RS256-only, while RFC 7009 must continue accepting legacy
    HS256 tokens during the compatibility window.  Using SimpleJWT's
    ``RefreshToken``/``AccessToken`` directly for every token silently rejects
    current RS256 refresh tokens and turns revocation into a no-op.
    """
    if token_type == 'refresh':
        return _decode_oauth_refresh_token(encoded)

    import jwt as _jwt

    try:
        alg = _jwt.get_unverified_header(encoded).get('alg')
    except Exception as exc:
        raise ValueError(f'invalid access-token header: {exc}') from exc
    if alg == 'RS256':
        payload = _jwt.decode(
            encoded,
            get_signing_material()['public_pem'],
            algorithms=['RS256'],
            options={'verify_aud': False},
        )
        if payload.get('token_type') != 'access':
            raise ValueError('token is not an access token')
        return payload
    if alg == 'HS256':
        return AccessToken(encoded)
    raise ValueError(f'unsupported access-token alg {alg!r}')


def _oauth_jwt_encode(payload: dict) -> str:
    """Encode an OIDC ID token with the public JWKS-backed signing key."""
    return _rs256_encode(payload)


def _scope_tokens(scope: str) -> set[str]:
    if not scope:
        return set()
    if scope == '*':
        return {'*'}
    return {part for part in str(scope).split() if part}


def _oidc_claims_for_user(
    user,
    *,
    memberships: dict | None = None,
    project_ids: list[int] | None = None,
    project_roles: dict[str, str] | None = None,
) -> dict:
    """
    Claims Forgejo Origin needs for per-agent SSO/provisioning.

    shizuha-admin is the durable org/team source; while the Phase-1 login path
    only has org-role memberships available in shizuha-id, keep the shape stable
    for the follow-on origin-provisioner by exposing role + team-list fields.
    """
    if (
        not isinstance(memberships, dict)
        or not isinstance(project_ids, list)
        or not isinstance(project_roles, dict)
    ):
        memberships, project_ids, project_roles = _fetch_membership_projection(user)
    org_ids = sorted(memberships.keys(), key=str)
    primary_org_id = org_ids[0] if org_ids else None
    display_name = (f"{user.first_name} {user.last_name}".strip() or user.username)
    roles = sorted({role for role in memberships.values() if role})
    team_memberships: list[str] = []

    # Flat `groups` claim for Forgejo OIDC group sync: Forgejo maps the values of
    # a single claim (default `groups`) to orgs/teams, so the structured
    # org/role/team fields above aren't usable for that mapping on first login
    # (rei cycle-1 P2). Emit prefixed, deterministic identifiers so a Forgejo
    # admin can map by org, org+role, role, or team unambiguously.
    groups = sorted({
        *(f'org:{org_id}' for org_id in memberships),
        *(f'org:{org_id}:{role}' for org_id, role in memberships.items() if role),
        *(f'role:{role}' for role in roles),
        *team_memberships,
    })

    return {
        'sub': str(user.pk),
        'username': user.username,
        'preferred_username': user.username,
        'email': user.email,
        'email_verified': True,
        'display_name': display_name,
        'name': display_name,
        'given_name': getattr(user, 'first_name', '') or '',
        'family_name': getattr(user, 'last_name', '') or '',
        'org_id': primary_org_id,
        'organization_id': primary_org_id,
        'organization_memberships': memberships,
        'project_ids': project_ids,
        'project_roles': project_roles,
        'roles': roles,
        'team_memberships': team_memberships,
        'groups': groups,
        'is_agent': _is_agent_user(user),
        'agent': _is_agent_user(user),
    }


def _mint_id_token(
    user,
    client: OAuthClient,
    issuer: str,
    scope: str,
    nonce: str = '',
    ttl_minutes: int = DEFAULT_ACCESS_TTL_MINUTES,
    claims: dict | None = None,
) -> str:
    now = int(timezone.now().timestamp())
    claims = claims or _oidc_claims_for_user(user)
    scope_set = _scope_tokens(scope)
    payload = {
        'iss': issuer,
        'sub': claims['sub'],
        'aud': client.client_id,
        'iat': now,
        'exp': now + ttl_minutes * 60,
        'auth_time': now,
    }
    if nonce:
        payload['nonce'] = nonce
    if 'profile' in scope_set:
        payload.update({
            'username': claims['username'],
            'preferred_username': claims['preferred_username'],
            'display_name': claims['display_name'],
            'name': claims['name'],
            'given_name': claims['given_name'],
            'family_name': claims['family_name'],
            'is_agent': claims['is_agent'],
            'agent': claims['agent'],
        })
    if 'email' in scope_set:
        payload.update({
            'email': claims['email'],
            'email_verified': claims['email_verified'],
        })
    if 'groups' in scope_set or 'profile' in scope_set:
        payload.update({
            'org_id': claims['org_id'],
            'organization_id': claims['organization_id'],
            'organization_memberships': claims['organization_memberships'],
            'roles': claims['roles'],
            'team_memberships': claims['team_memberships'],
            'groups': claims['groups'],
        })
    return _oauth_jwt_encode(payload)


def _mint_tokens(user, client: OAuthClient, scope: str, issuer: str,
                 access_ttl_minutes: int | None = None,
                 refresh_ttl_days: int = DEFAULT_REFRESH_TTL_DAYS,
                 user_agent: str = '',
                 nonce: str = '',
                 token_family: str = '',
                 device: 'OAuthDevice | None' = None) -> dict:
    """
    Mint JWT access + refresh tokens with standard claims + OAuth metadata.

    OAuth tokens are always RS256/JWKS signed. ``SHIZUHA_OAUTH_RS256`` remains
    in deployment values for one rollback release, but it no longer selects a
    symmetric signing path (ID-61 / CTX-452 prevention).
    """
    membership_projection = _fetch_membership_projection(user)
    memberships, project_ids, project_roles = membership_projection

    if access_ttl_minutes is None:
        access_ttl_minutes = getattr(
            client, 'access_token_ttl_minutes', DEFAULT_ACCESS_TTL_MINUTES,
        )
    # Bound bad legacy/admin values without allowing a client to exceed the
    # established OAuth maximum or mint an already-expired token.
    access_ttl_minutes = max(
        1, min(int(access_ttl_minutes), DEFAULT_ACCESS_TTL_MINUTES),
    )

    # Build SimpleJWT token objects for their claim helpers only. Never stringify
    # them: SimpleJWT's project default is HS256. Re-encode both payloads through
    # the sole OAuth signing primitive below.
    # Do not use SimpleJWT's per-user refresh factory here: its blacklist mixin
    # serializes an OutstandingToken with the project-wide HS256 backend as a
    # side effect. OAuth maintains its own IssuedRefreshToken ledger below, so
    # construct the claim carrier directly and set the principal explicitly.
    # This keeps the stronger invariant literal: ID does not mint even a hidden
    # database-only HS256 OAuth token while returning RS256 to the caller.
    refresh = RefreshToken()
    refresh['user_id'] = user.pk
    _populate_standard_claims(
        refresh,
        user,
        membership_projection=membership_projection,
    )
    _populate_enabled_services(refresh, user)
    oidc_claims = _oidc_claims_for_user(
        user,
        memberships=memberships,
        project_ids=project_ids,
        project_roles=project_roles,
    )
    for key, value in oidc_claims.items():
        refresh[key] = value
    refresh.set_exp(lifetime=timedelta(days=refresh_ttl_days))
    refresh['scope'] = scope
    refresh['client_id'] = client.client_id
    refresh['iss'] = issuer
    refresh['aud'] = client.client_id if 'openid' in _scope_tokens(scope) else (
        scope.split() if scope != '*' else '*'
    )
    # DRV-106: refresh-family + device binding claims. ``token_family`` is the
    # stable family id shared by every descendant of one original grant.
    if token_family:
        refresh['token_family'] = token_family
    if device is not None:
        refresh['device_id'] = device.device_id

    access = AccessToken()
    access.set_exp(lifetime=timedelta(minutes=access_ttl_minutes))
    online_userinfo_client = client.client_name in getattr(
        settings, 'OAUTH_ONLINE_USERINFO_CLIENT_NAMES', frozenset(),
    )
    for key in (
        'user_id', 'email', 'username', 'first_name', 'last_name',
        'is_staff', 'is_superuser', 'is_agent', 'agent',
        'preferred_username', 'display_name', 'name', 'given_name', 'family_name',
        'email_verified', 'org_id', 'organization_id', 'roles',
        'team_memberships', 'enabled_services', 'organization_memberships',
        'project_ids', 'project_roles',
        'token_version',
        'scope', 'client_id', 'iss', 'aud',
    ):
        # Stalwart calls userinfo when its configured identity claim is absent.
        # That online lookup enforces ID lifecycle state immediately; retaining
        # ``email`` here would let Stalwart accept the JWT entirely offline until
        # expiry plus its fixed validation leeway.
        if key == 'email' and online_userinfo_client:
            continue
        if key in refresh:
            access[key] = refresh[key]
    access['token_type'] = 'access'
    # DRV-106 audience contract: the Drive Desktop client's access tokens carry
    # the Drive-resource audience (not the OAuth client id / OIDC ID-token
    # audience) so Drive accepts them verbatim and rejects client-id-only or
    # wrong-audience tokens.
    if _is_drive_desktop_client(client):
        access['aud'] = [DRIVE_RESOURCE_AUDIENCE]

    access_str = _rs256_encode(dict(access.payload))
    refresh_str = _rs256_encode(dict(refresh.payload))

    refresh_jti = refresh.get('jti')
    refresh_exp = refresh.get('exp')
    if refresh_jti and refresh_exp:
        IssuedRefreshToken.objects.get_or_create(
            jti=refresh_jti,
            defaults={
                'user': user,
                'client': client,
                'scope': scope,
                'expires_at': datetime.fromtimestamp(refresh_exp, tz=_dt_timezone.utc),
                'user_agent': user_agent[:500],
                'token_family': token_family,
                'device': device,
            },
        )

    response = {
        'access_token': access_str,
        'refresh_token': refresh_str,
        'token_type': 'Bearer',
        'expires_in': access_ttl_minutes * 60,
        'scope': scope,
    }
    if 'openid' in _scope_tokens(scope):
        response['id_token'] = _mint_id_token(
            user,
            client,
            issuer,
            scope,
            nonce=nonce,
            ttl_minutes=access_ttl_minutes,
            claims=oidc_claims,
        )
    return response


# ──────────────────────────────────────────────────────────── Discovery

class AuthorizationServerMetadataView(APIView):
    """RFC 8414 /.well-known/oauth-authorization-server."""
    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    def get(self, request):
        issuer = _issuer_url(request)
        return Response({
            'issuer': issuer,
            'authorization_endpoint': f'{issuer}/oauth/authorize',
            'token_endpoint': f'{issuer}/api/oauth/token',
            'registration_endpoint': f'{issuer}/api/oauth/register',
            'userinfo_endpoint': f'{issuer}/api/oauth/userinfo',
            'revocation_endpoint': f'{issuer}/api/oauth/revoke',
            'jwks_uri': f'{issuer}/.well-known/jwks.json',
            'scopes_supported': ['*', 'openid', 'profile', 'email', 'groups'],
            'response_types_supported': ['code'],
            'grant_types_supported': [
                'authorization_code', 'refresh_token', 'password', 'client_credentials',
                'urn:ietf:params:oauth:grant-type:token-exchange',
            ],
            'code_challenge_methods_supported': ['S256', 'plain'],
            'code_challenge_methods_drive_desktop': ['S256'],
            'token_endpoint_auth_methods_supported': [
                'none', 'client_secret_post', 'client_secret_basic',
            ],
            'id_token_signing_alg_values_supported': ['RS256'],
            'subject_types_supported': ['public'],
            'claims_supported': [
                'sub', 'username', 'preferred_username', 'email',
                'email_verified', 'display_name', 'name', 'given_name',
                'family_name', 'org_id', 'organization_id',
                'organization_memberships', 'roles', 'team_memberships',
                'is_agent', 'agent',
            ],
            'service_documentation': f'{issuer}/api/docs/',
        })


class JWKSView(APIView):
    """RFC 8414: JSON Web Key Set endpoint for RS256 public-key discovery."""
    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    def get(self, request):
        return Response(build_jwks())


# ──────────────────────────────────────────── Dynamic Client Registration

class ClientRegistrationView(APIView):
    """RFC 7591 dynamic client registration. Public, rate-limited in front."""
    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    def post(self, request):
        data = request.data or {}
        client_name = (data.get('client_name') or 'unknown-client').strip()[:200]
        redirect_uris = data.get('redirect_uris') or []
        if not isinstance(redirect_uris, list) or not redirect_uris:
            return Response(
                {'error': 'invalid_client_metadata',
                 'error_description': 'redirect_uris must be a non-empty list'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        for uri in redirect_uris:
            if not isinstance(uri, str) or len(uri) > 2000:
                return Response(
                    {'error': 'invalid_redirect_uri',
                     'error_description': f'bad uri: {uri!r}'},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        token_endpoint_auth_method = data.get('token_endpoint_auth_method', 'none')
        client_type = (
            OAuthClient.CLIENT_TYPE_PUBLIC
            if token_endpoint_auth_method == 'none'
            else OAuthClient.CLIENT_TYPE_CONFIDENTIAL
        )
        grant_types = data.get('grant_types') or ['authorization_code', 'refresh_token']
        # PLAT-356 security (ren): public/unauthenticated dynamic client registration
        # must NOT be able to self-provision a machine-to-machine
        # (client_credentials) client — that would let any anonymous caller mint
        # RS256 service tokens with arbitrary aud/scope. M2M clients are provisioned
        # out-of-band (admin/internal seeding), never via this public endpoint.
        if 'client_credentials' in [g.strip() for g in grant_types if isinstance(g, str)]:
            return Response(
                {'error': 'invalid_client_metadata',
                 'error_description': 'the client_credentials grant cannot be requested via '
                                      'public dynamic client registration; M2M/service clients '
                                      'are provisioned out-of-band'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        response_types = data.get('response_types') or ['code']
        scope = data.get('scope') or '*'

        client_id = _gen_token(24)
        client_secret = ''
        client_secret_hash = ''
        if client_type == OAuthClient.CLIENT_TYPE_CONFIDENTIAL:
            client_secret = _gen_token(32)
            client_secret_hash = hashlib.sha256(client_secret.encode()).hexdigest()

        client = OAuthClient.objects.create(
            client_id=client_id,
            client_secret_hash=client_secret_hash,
            client_name=client_name,
            redirect_uris=redirect_uris,
            grant_types=grant_types,
            response_types=response_types,
            scope=scope,
            client_type=client_type,
        )

        resp = {
            'client_id': client.client_id,
            'client_name': client.client_name,
            'redirect_uris': client.redirect_uris,
            'grant_types': client.grant_types,
            'response_types': client.response_types,
            'scope': client.scope,
            'token_endpoint_auth_method': token_endpoint_auth_method,
        }
        if client_secret:
            resp['client_secret'] = client_secret
        return Response(resp, status=status.HTTP_201_CREATED)


# ───────────────────────────────────────────────────── Authorization flow

def _validate_authorize_params(data) -> tuple[OAuthClient | None, str | None, dict | None]:
    """Shared validation. Returns (client, error_json, resolved_params)."""
    client_id = data.get('client_id')
    redirect_uri = data.get('redirect_uri')
    response_type = data.get('response_type', 'code')
    if not client_id:
        return None, {'error': 'invalid_request', 'error_description': 'client_id required'}, None
    if response_type != 'code':
        return None, {'error': 'unsupported_response_type'}, None
    try:
        client = OAuthClient.objects.get(client_id=client_id)
    except OAuthClient.DoesNotExist:
        return None, {'error': 'invalid_client'}, None
    if not redirect_uri or not client.redirect_uri_allowed(redirect_uri):
        return None, {'error': 'invalid_redirect_uri',
                      'error_description': f'redirect_uri not allowed for this client'}, None

    code_challenge = data.get('code_challenge')
    code_challenge_method = data.get('code_challenge_method', 'S256')
    if client.client_type == OAuthClient.CLIENT_TYPE_PUBLIC and not code_challenge:
        return None, {'error': 'invalid_request',
                      'error_description': 'code_challenge required for public clients'}, None
    if code_challenge_method not in ('S256', 'plain'):
        return None, {'error': 'invalid_request',
                      'error_description': 'unsupported code_challenge_method'}, None
    # DRV-106: the Drive Desktop client is PKCE S256-only — missing/plain
    # challenges fail closed (DRV-104 HLD v2.5 §7).
    if _is_drive_desktop_client(client) and code_challenge_method != 'S256':
        return None, {'error': 'invalid_request',
                      'error_description': 'Drive Desktop requires PKCE S256'}, None
    # DRV-106: the Drive Desktop client only accepts loopback redirects
    # (127.0.0.1 / [::1], any ephemeral port).
    if _is_drive_desktop_client(client) and not _is_loopback_redirect(redirect_uri):
        return None, {'error': 'invalid_redirect_uri',
                      'error_description': 'Drive Desktop requires a loopback redirect URI'}, None

    scope = (data.get('scope') or client.scope or '*').strip()
    state = data.get('state', '')
    nonce = data.get('nonce', '')

    return client, None, {
        'redirect_uri': redirect_uri,
        'scope': scope,
        'state': state,
        'code_challenge': code_challenge or '',
        'code_challenge_method': code_challenge_method,
        'nonce': nonce,
    }


class AuthorizeInfoView(APIView):
    """
    Frontend calls this on /oauth/authorize page load to resolve client
    metadata and validate the request before showing consent.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        client, err, params = _validate_authorize_params(request.query_params)
        if err:
            return Response(err, status=status.HTTP_400_BAD_REQUEST)
        return Response({
            'client': {
                'client_id': client.client_id,
                'client_name': client.client_name,
                'is_system': client.is_system,
            },
            'redirect_uri': params['redirect_uri'],
            'scope': params['scope'],
            'state': params['state'],
            'user': {
                'id': request.user.id,
                'username': request.user.username,
                'email': request.user.email,
            },
        })


class AuthorizeApproveView(APIView):
    """
    Issue an authorization code after the user clicks "Allow" on the consent
    page. Caller is the authenticated user's browser session.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        client, err, params = _validate_authorize_params(request.data)
        if err:
            return Response(err, status=status.HTTP_400_BAD_REQUEST)

        code = _gen_token(32)
        AuthorizationCode.objects.create(
            code=code,
            client=client,
            user=request.user,
            redirect_uri=params['redirect_uri'],
            scope=params['scope'],
            code_challenge=params['code_challenge'],
            code_challenge_method=params['code_challenge_method'],
            nonce=params['nonce'],
            expires_at=timezone.now() + timedelta(seconds=AUTH_CODE_TTL_SECONDS),
        )

        q = {'code': code}
        if params['state']:
            q['state'] = params['state']
        separator = '&' if '?' in params['redirect_uri'] else '?'
        redirect_url = f"{params['redirect_uri']}{separator}{urlencode(q)}"

        logger.info(
            f"OAuth code issued to client={client.client_id} user={request.user.email}"
        )
        return Response({'redirect_url': redirect_url, 'code': code})


# ───────────────────────────────────────────────────────────── Token endpoint


def _authenticate_subject_access_token(raw_token: str):
    """Validate a subject access token (HS256 SimpleJWT or RS256 OAuth)."""
    from rest_framework.exceptions import AuthenticationFailed as DRFAuthFailed

    class _Req:
        def __init__(self, token: str):
            self.META = {'HTTP_AUTHORIZATION': f'Bearer {token}'}

    try:
        result = RS256OAuthBearerAuthentication().authenticate(_Req(raw_token))
    except DRFAuthFailed:
        return None, None
    except Exception:
        return None, None
    if not result:
        return None, None
    return result[0], result[1]


class TokenView(APIView):
    """POST /oauth/token — the RFC 6749 token endpoint."""
    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    def post(self, request):
        data = request.data or {}
        grant_type = data.get('grant_type')
        issuer = _issuer_url(request)

        if grant_type == 'authorization_code':
            return self._grant_authorization_code(data, issuer)
        if grant_type == 'refresh_token':
            return self._grant_refresh_token(data, issuer)
        if grant_type == 'password':
            return self._grant_password(data, issuer)
        if grant_type == 'client_credentials':
            return self._grant_client_credentials(data, issuer)
        if grant_type == 'urn:ietf:params:oauth:grant-type:token-exchange':
            return self._grant_token_exchange(data, issuer)
        return Response(
            {'error': 'unsupported_grant_type'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    def _basic_client_credentials(self) -> tuple[str, str] | None:
        auth = self.request.META.get('HTTP_AUTHORIZATION', '')
        if not auth.lower().startswith('basic '):
            return None
        try:
            decoded = base64.b64decode(auth.split(' ', 1)[1]).decode('utf-8')
            client_id, client_secret = decoded.split(':', 1)
            return unquote_plus(client_id), unquote_plus(client_secret)
        except Exception:
            return None

    def _authenticate_client(self, data) -> tuple[OAuthClient | None, Response | None]:
        basic = self._basic_client_credentials()
        if basic:
            client_id, client_secret = basic
        else:
            client_id = data.get('client_id')
            client_secret = data.get('client_secret', '')
        if not client_id:
            return None, Response(
                {'error': 'invalid_client', 'error_description': 'client_id required'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            client = OAuthClient.objects.get(client_id=client_id)
        except OAuthClient.DoesNotExist:
            return None, Response(
                {'error': 'invalid_client'},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        if client.client_type == OAuthClient.CLIENT_TYPE_CONFIDENTIAL:
            # PLAT-356 (akira P3): a confidential client with no stored secret hash must
            # NEVER authenticate — compare_digest('','') would otherwise accept an empty
            # secret. Reject misconfigured/secret-less confidential clients outright.
            if not client.client_secret_hash:
                return None, Response(
                    {'error': 'invalid_client', 'error_description': 'client has no credential configured'},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
            supplied = hashlib.sha256(client_secret.encode()).hexdigest() if client_secret else ''
            if not secrets.compare_digest(supplied, client.client_secret_hash or ''):
                return None, Response(
                    {'error': 'invalid_client'},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
        return client, None

    def _grant_authorization_code(self, data, issuer):
        client, err = self._authenticate_client(data)
        if err:
            return err

        code_value = data.get('code')
        redirect_uri = data.get('redirect_uri')
        code_verifier = data.get('code_verifier', '')
        if not code_value or not redirect_uri:
            return Response(
                {'error': 'invalid_request'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            auth_code = AuthorizationCode.objects.select_related('user').get(
                code=code_value, client=client,
            )
        except AuthorizationCode.DoesNotExist:
            return Response({'error': 'invalid_grant'}, status=status.HTTP_400_BAD_REQUEST)
        if auth_code.is_used():
            return Response(
                {'error': 'invalid_grant', 'error_description': 'code already used'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if auth_code.is_expired():
            return Response(
                {'error': 'invalid_grant', 'error_description': 'code expired'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if auth_code.redirect_uri != redirect_uri:
            return Response(
                {'error': 'invalid_grant', 'error_description': 'redirect_uri mismatch'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if auth_code.code_challenge and not _verify_pkce(
            code_verifier, auth_code.code_challenge, auth_code.code_challenge_method,
        ):
            return Response(
                {'error': 'invalid_grant', 'error_description': 'PKCE verification failed'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        ua = self.request.META.get('HTTP_USER_AGENT', '')
        # DRV-106: the Drive Desktop client gets a fresh refresh-family and an
        # optional device binding on the initial authorization-code grant.
        token_family = ''
        device = None
        if _is_drive_desktop_client(client):
            token_family = secrets.token_urlsafe(32)
            device_id = (data.get('device_id') or '').strip()
            if device_id:
                device, _ = OAuthDevice.objects.get_or_create(
                    user=auth_code.user,
                    device_id=device_id,
                    defaults={
                        'client': client,
                        'name': (data.get('device_name') or '')[:255],
                        'os': (data.get('device_os') or '')[:100],
                        'build': (data.get('device_build') or '')[:100],
                        'last_seen_at': timezone.now(),
                    },
                )
                if not device.is_active:
                    return Response(
                        {'error': 'invalid_grant',
                         'error_description': 'device revoked'},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
        tokens = _mint_tokens(
            auth_code.user,
            client,
            auth_code.scope,
            issuer,
            user_agent=ua,
            nonce=getattr(auth_code, 'nonce', '') or '',
            token_family=token_family,
            device=device,
        )
        # Consume the one-time grant only after the complete membership
        # projection has been read and all tokens have been built.
        auth_code.used_at = timezone.now()
        auth_code.save(update_fields=['used_at'])
        logger.info(
            f"OAuth tokens minted (auth_code) client={client.client_id} "
            f"user={auth_code.user.email}"
        )
        return Response(tokens)

    def _grant_refresh_token(self, data, issuer):
        # For public clients, client_id is required but no secret.
        refresh_str = data.get('refresh_token')
        if not refresh_str:
            return Response({'error': 'invalid_request'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            refresh = _decode_oauth_refresh_token(refresh_str)
        except Exception as exc:
            return Response(
                {'error': 'invalid_grant', 'error_description': str(exc)},
                status=status.HTTP_400_BAD_REQUEST,
            )

        jti = refresh.get('jti')
        if jti and RevokedToken.objects.filter(jti=jti).exists():
            # DRV-106: replay of a revoked refresh token revokes the whole
            # family (fail-closed) — no parallel valid descendants remain.
            token_family = refresh.get('token_family') or ''
            if token_family:
                try:
                    client_id = refresh.get('client_id') or data.get('client_id')
                    client = OAuthClient.objects.get(client_id=client_id)
                except (OAuthClient.DoesNotExist, TypeError):
                    client = None
                user_id = refresh.get('user_id')
                user = None
                if user_id:
                    try:
                        user = User.objects.get(pk=user_id)
                    except User.DoesNotExist:
                        user = None
                if user is not None and client is not None:
                    _revoke_refresh_family(
                        user=user, client=client, token_family=token_family,
                        reason='refresh-token replay',
                    )
            return Response(
                {'error': 'invalid_grant', 'error_description': 'token revoked'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        client_id = refresh.get('client_id') or data.get('client_id')
        if not client_id:
            return Response(
                {'error': 'invalid_request',
                 'error_description': 'client_id required'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            client = OAuthClient.objects.get(client_id=client_id)
        except OAuthClient.DoesNotExist:
            return Response({'error': 'invalid_client'}, status=status.HTTP_401_UNAUTHORIZED)
        if _oauth_token_precedes_client_cutoff(refresh, client):
            return Response(
                {'error': 'invalid_grant', 'error_description': 'client revoked'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if client.client_type == OAuthClient.CLIENT_TYPE_CONFIDENTIAL:
            basic = self._basic_client_credentials()
            supplied_secret = basic[1] if basic and basic[0] == client.client_id else (
                data.get('client_secret') or ''
            )
            supplied = hashlib.sha256(supplied_secret.encode()).hexdigest()
            if not secrets.compare_digest(supplied, client.client_secret_hash or ''):
                return Response({'error': 'invalid_client'}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            user = User.objects.get(pk=refresh['user_id'])
        except User.DoesNotExist:
            return Response({'error': 'invalid_grant'}, status=status.HTTP_400_BAD_REQUEST)

        # DRV-106: refresh-family rotation. The consumed token is revoked and
        # its family/device carried into the descendant. Reuse of an
        # already-consumed/revoked token revokes the WHOLE family (fail-closed
        # replay response) — no parallel valid descendants remain.
        token_family = refresh.get('token_family') or ''
        device_id_claim = refresh.get('device_id') or ''
        device = None
        if device_id_claim:
            device = (
                OAuthDevice.objects
                .filter(user=user, device_id=device_id_claim, is_active=True)
                .first()
            )
            if device is None:
                # A revoked/unknown device cannot refresh — fail closed.
                return Response(
                    {'error': 'invalid_grant',
                     'error_description': 'device revoked'},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        if jti:
            issued = IssuedRefreshToken.objects.filter(jti=jti).first()
            if issued is not None and issued.revoked_at is not None:
                # Replay of an already-consumed token → revoke the family.
                _revoke_refresh_family(
                    user=user, client=client, token_family=token_family,
                    reason='refresh-token replay',
                )
                return Response(
                    {'error': 'invalid_grant',
                     'error_description': 'token already used; family revoked'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            if token_family:
                # If any sibling in this family was already consumed by a
                # rotation, a stale token replay must not mint a parallel
                # descendant. A family with an active (unrevoked) descendant
                # means this token was superseded.
                family_active = (
                    IssuedRefreshToken.objects
                    .filter(user=user, client=client, token_family=token_family,
                            revoked_at__isnull=True, expires_at__gt=timezone.now())
                    .exclude(jti=jti)
                    .exists()
                )
                if family_active:
                    _revoke_refresh_family(
                        user=user, client=client, token_family=token_family,
                        reason='refresh-token replay (superseded)',
                    )
                    return Response(
                        {'error': 'invalid_grant',
                         'error_description': 'token already used; family revoked'},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

        scope = refresh.get('scope') or data.get('scope') or '*'
        ua = self.request.META.get('HTTP_USER_AGENT', '')
        tokens = _mint_tokens(
            user, client, scope, issuer, user_agent=ua,
            token_family=token_family, device=device,
        )
        # A transient projection outage returns 503 without consuming or
        # advancing the caller's existing refresh-token ledger entry.
        if jti:
            now = timezone.now()
            IssuedRefreshToken.objects.filter(jti=jti).update(
                last_used_at=now,
                revoked_at=now,
            )
            RevokedToken.objects.get_or_create(
                jti=jti,
                defaults={
                    'token_type': 'refresh',
                    'user': user,
                    'client': client,
                    'reason': 'refresh rotation',
                },
            )
        if device is not None:
            device.last_seen_at = timezone.now()
            device.save(update_fields=['last_seen_at', 'updated_at'])
        logger.info(
            f"OAuth tokens refreshed client={client.client_id} user={user.email}"
        )
        return Response(tokens)

    def _grant_password(self, data, issuer):
        """Legacy compat — wraps LoginView's username/password auth."""
        from django.contrib.auth import authenticate
        client, err = self._authenticate_client(data)
        if err:
            return err
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            return Response({'error': 'invalid_request'}, status=status.HTTP_400_BAD_REQUEST)
        user = authenticate(username=username, password=password)
        if not user:
            try:
                by_email = User.objects.get(email__iexact=username)
                user = authenticate(username=by_email.username, password=password)
            except User.DoesNotExist:
                user = None
        if not user:
            return Response(
                {'error': 'invalid_grant', 'error_description': 'bad credentials'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        scope = data.get('scope') or client.scope or '*'
        ua = self.request.META.get('HTTP_USER_AGENT', '')
        tokens = _mint_tokens(user, client, scope, issuer, user_agent=ua)
        logger.info(
            f"OAuth tokens minted (password) client={client.client_id} user={user.email}"
        )
        return Response(tokens)

    def _grant_client_credentials(self, data, issuer):
        """PLAT-356 / PLAT-352 HLD §3 — M2M service-to-service grant.

        Mints a short-TTL (<=15m) SERVICE-identity RS256 access token for a confidential
        client. No user, and NO refresh token (RFC 6749 §4.4.3). Scope is the requested
        scope intersected with the client's registered grant (default-deny); aud carries
        the target service(s) named by the <service>:<resource>.<verb> scope grammar.
        Service identity is kept distinct from per-agent identity (PLAT-45 ladder) — this
        token carries no user claims and is marked is_service."""
        client, err = self._authenticate_client(data)
        if err:
            return err
        # Confidential clients only — a public (secret-less) client must never get M2M tokens.
        if client.client_type != OAuthClient.CLIENT_TYPE_CONFIDENTIAL:
            return Response(
                {'error': 'unauthorized_client',
                 'error_description': 'client_credentials requires a confidential client'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if 'client_credentials' not in (client.grant_types or []):
            return Response(
                {'error': 'unauthorized_client',
                 'error_description': 'client not registered for the client_credentials grant'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        # akira P1: an emergency-revoked client must NOT mint. M2M tokens have no refresh, so
        # refuse-to-mint is the kill-switch (aoi arbitration 2026-06-20: M2M revocation is the
        # existing access_revoked_before cutoff + RevokedToken jti — NOT a token_version field;
        # none exists in this codebase, ID-7 didn't add one) —
        # a set access_revoked_before (PLAT-47 emergency revocation) means the client is
        # revoked, so deny new tokens. (Security note for akira: this treats ANY set cutoff
        # as "revoked, no new tokens"; re-enable by clearing the cutoff. Flag if you'd
        # prefer point-in-time access_revoked_before >= now semantics instead.)
        if client.access_revoked_before is not None:
            return Response(
                {'error': 'invalid_client', 'error_description': 'client revoked'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        # Scope (akira P2): least-privilege — require EXPLICIT <service>:<resource>.<verb>
        # scopes. Reject wildcard '*' both as the client's registered scope and in the
        # request (a '*' aud would make the token valid for EVERY service).
        granted = (client.scope or '').split()
        if '*' in granted:
            return Response(
                {'error': 'invalid_scope',
                 'error_description': 'client_credentials requires explicit per-service scopes; a wildcard "*" client scope is not allowed (least-privilege, PLAT-352 §3)'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        requested_raw = data.get('scope')
        requested = str(requested_raw or '').split()
        if not requested or '*' in requested:
            return Response(
                {'error': 'invalid_scope',
                 'error_description': 'explicit non-empty <service>:<resource>.<verb> scope(s) required for client_credentials; "*" is not allowed'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        ungranted = [sc for sc in requested if sc not in granted]
        if ungranted:
            return Response(
                {'error': 'invalid_scope',
                 'error_description': 'scope(s) not granted: ' + ' '.join(ungranted)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        scope = ' '.join(requested)
        # aud = the target service(s): the <service> prefix of each granted scope
        # (e.g. 'admin' from 'admin:org.read'); fall back to the raw scope if unprefixed.
        aud = sorted({sc.split(':', 1)[0] for sc in requested if ':' in sc}) or requested

        ttl_minutes = 15  # M2M tokens are short-TTL per PLAT-352 §3 (<=15m); no refresh.
        now = datetime.now(tz=_dt_timezone.utc)
        payload = {
            'token_type': 'access',
            'sub': 'service:' + client.client_id,   # SERVICE identity — never a user (PLAT-45)
            'client_id': client.client_id,
            'is_service': True,
            'scope': scope,
            'aud': aud,
            'iss': issuer,
            'iat': int(now.timestamp()),
            'exp': int((now + timedelta(minutes=ttl_minutes)).timestamp()),
            'jti': secrets.token_urlsafe(16),
            # PLAT-356 (akira P1b -> aoi arbitration 2026-06-20): M2M revocation is the existing
            # cutoff + jti mechanism, NOT a token_version field (none exists in this codebase).
            # This token carries client_id + iat + jti, so it is already covered:
            #   * emergency "revoke all outstanding for a client" = set
            #     OAuthClient.access_revoked_before = now -> every token with iat <= cutoff is
            #     rejected by the cutoff verifier (OAuthClientRevocationJWTAuthentication /
            #     RS256OAuthBearerAuthentication) and reported revoked by the
            #     /api/oauth/revocation-status endpoint resource servers call; refuse-to-mint
            #     above blocks new tokens. (Functionally equivalent to "bump token_version".)
            #   * point-revoke a single token = RevokedToken by jti (RFC 7009).
        }
        # M2M is RS256/JWKS-only by design (no shared secret — the whole point of §3).
        access_str = _rs256_encode(payload)
        logger.info(
            f"OAuth M2M token minted (client_credentials) client={client.client_id} "
            f"scope={scope!r} aud={aud}"
        )
        return Response({
            'access_token': access_str,
            'token_type': 'Bearer',
            'expires_in': ttl_minutes * 60,
            'scope': scope,
        })


    def _grant_token_exchange(self, data, issuer):
        """MAIL-74 / MAIL-73: self-only delegated access token for shizuha-mail.

        Caller presents a valid current ID access token (Bearer or
        subject_token). ID re-checks active lifecycle + effective ``mail``
        entitlement, then mints an access-only RS256 token for the existing
        ``shizuha-mail`` OAuth client with Stalwart-accepted scopes
        ``openid email``, audience = that client's id, TTL <= 60s.
        No refresh token. Fail-closed on any check failure.
        """
        from rest_framework.exceptions import AuthenticationFailed as DRFAuthFailed

        from .authentication import _enforce_user_revocation
        from .lifecycle import LifecycleState, derive_lifecycle_state
        from .services import get_effective_services

        subject_token = ''
        auth = self.request.META.get('HTTP_AUTHORIZATION', '')
        if auth.lower().startswith('bearer '):
            subject_token = auth.split(' ', 1)[1].strip()
        if not subject_token:
            subject_token = (data.get('subject_token') or '').strip()
        if not subject_token:
            return Response(
                {
                    'error': 'invalid_request',
                    'error_description': 'subject access token required (Authorization Bearer or subject_token)',
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        subject_token_type = (data.get('subject_token_type') or
                              'urn:ietf:params:oauth:token-type:access_token')
        if subject_token_type not in (
            'urn:ietf:params:oauth:token-type:access_token',
            'access_token',
            '',
        ):
            return Response(
                {
                    'error': 'invalid_request',
                    'error_description': 'subject_token_type must be access_token',
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        user, validated = _authenticate_subject_access_token(subject_token)
        if user is None or validated is None:
            return Response(
                {'error': 'invalid_grant', 'error_description': 'subject token invalid or expired'},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        claims = validated if isinstance(validated, dict) else getattr(validated, 'payload', validated)
        # MAIL-74: delegated tokens are access-only and must not be renewable as
        # their own subject (no implicit refresh via re-exchange).
        if isinstance(claims, dict) and claims.get('token_use') == 'mail_delegated':
            return Response(
                {
                    'error': 'invalid_grant',
                    'error_description': 'mail delegated tokens cannot be exchanged as subject tokens',
                },
                status=status.HTTP_403_FORBIDDEN,
            )
        if getattr(user, 'is_service', False) or (isinstance(claims, dict) and claims.get('is_service')):
            return Response(
                {'error': 'invalid_grant', 'error_description': 'service principals cannot exchange for mail tokens'},
                status=status.HTTP_403_FORBIDDEN,
            )
        if not getattr(user, 'is_active', False):
            return Response(
                {'error': 'invalid_grant', 'error_description': 'user is inactive'},
                status=status.HTTP_403_FORBIDDEN,
            )

        try:
            # Re-read authoritative lifecycle state at exchange time.  Do not
            # fall back to ``user.is_active`` when the profile is missing or
            # the database lookup fails: that would mint through an unknown
            # lifecycle state at the mail trust boundary.
            profile = UserProfile.objects.get(user_id=user.pk)
            life = profile.lifecycle_state or derive_lifecycle_state(
                profile.approval_status, user.is_active,
            )
        except UserProfile.DoesNotExist:
            return Response(
                {
                    'error': 'invalid_grant',
                    'error_description': 'user lifecycle profile is unavailable',
                },
                status=status.HTTP_403_FORBIDDEN,
            )
        except Exception:
            logger.exception(
                'token-exchange: lifecycle lookup failed user_id=%s',
                getattr(user, 'id', '?'),
            )
            return Response(
                {
                    'error': 'temporarily_unavailable',
                    'error_description': 'could not evaluate user lifecycle',
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        if life != LifecycleState.ACTIVE:
            return Response(
                {
                    'error': 'invalid_grant',
                    'error_description': 'user lifecycle is not active',
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        # Re-read the authoritative user cutoff at this mint boundary instead
        # of relying only on the authenticator's short-lived cache. A logout or
        # password-change must not let a previously issued platform bearer mint
        # a fresh Stalwart token while another worker still holds a cached
        # ``no cutoff`` sentinel.
        try:
            _enforce_user_revocation(
                profile.access_revoked_before,
                claims.get('iat') if isinstance(claims, dict) else None,
                DRFAuthFailed,
            )
        except DRFAuthFailed:
            return Response(
                {
                    'error': 'invalid_grant',
                    'error_description': 'subject access token revoked',
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        try:
            services = get_effective_services(user)
        except Exception:
            logger.exception('token-exchange: get_effective_services failed user_id=%s', getattr(user, 'id', '?'))
            return Response(
                {
                    'error': 'temporarily_unavailable',
                    'error_description': 'could not evaluate mail entitlement',
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        if 'mail' not in services:
            return Response(
                {
                    'error': 'access_denied',
                    'error_description': 'mail entitlement not granted',
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        # MAIL-74 P1: pin the immutable configured system client_id. client_name is
        # public/non-unique (dynamic registration can spoof "shizuha-mail").
        mail_client_id = (getattr(settings, 'SHIZUHA_MAIL_OAUTH_CLIENT_ID', '') or '').strip()
        if not mail_client_id:
            return Response(
                {
                    'error': 'server_error',
                    'error_description': 'SHIZUHA_MAIL_OAUTH_CLIENT_ID is not configured',
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        try:
            client = OAuthClient.objects.get(client_id=mail_client_id)
        except OAuthClient.DoesNotExist:
            return Response(
                {
                    'error': 'invalid_client',
                    'error_description': 'configured shizuha-mail OAuth client is not registered',
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        except OAuthClient.MultipleObjectsReturned:
            return Response(
                {
                    'error': 'server_error',
                    'error_description': 'configured shizuha-mail OAuth client_id is ambiguous',
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        if not client.is_system:
            return Response(
                {
                    'error': 'invalid_client',
                    'error_description': 'configured mail OAuth client is not a system client',
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        if client.access_revoked_before is not None:
            return Response(
                {'error': 'invalid_client', 'error_description': 'shizuha-mail client revoked'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # MAIL-122: the canonical managed mailbox is a SIGNED claim on this
        # token.  Stalwart is configured `claimUsername=email`, and v0.16.13
        # treats a JWT with no resolvable email as requiring a second
        # `/userinfo` request whose failure is FATAL to authentication
        # (crates/directory/src/backend/oidc/lookup.rs).  Omitting it therefore
        # made every JMAP/SMTP auth depend on Stalwart pod -> public-ID
        # reachability AFTER ID had already minted a valid 60s token — an
        # availability dependency with no security benefit, and the direct
        # cause of the MAIL-122 outage (JMAP session 401 while token exchange
        # was healthy).  With the claim signed, Stalwart validates the mailbox
        # identity offline and `/userinfo` becomes optional enrichment.
        #
        # This MUST be the canonical managed mailbox, never the user's external
        # or login address: `mailbox_address_for_user` derives it from the ID
        # username and keeps only the local part, so a legacy identity whose
        # username is an external email still yields `<local>@shizuha.com`.
        from .lifecycle import mailbox_address_for_user

        scope = 'openid email'
        ttl_seconds = 60
        now = datetime.now(tz=_dt_timezone.utc)
        issued_at = int(now.timestamp())
        # This token crosses the Stalwart trust boundary. Keep its claim set
        # deliberately smaller than a normal Shizuha access token: it carries
        # only the identity Stalwart must authenticate, while staff flags,
        # services, memberships, roles, groups, and profile data never leave ID.
        payload = {
            'iss': issuer,
            'sub': str(user.pk),
            # RS256OAuthBearerAuthentication uses this private identifier to
            # resolve the active subject for the optional /userinfo enrichment
            # lookup. It is the sole non-standard identity claim.
            'user_id': user.pk,
            'email': mailbox_address_for_user(user),
            'aud': client.client_id,
            'iat': issued_at,
            'exp': issued_at + ttl_seconds,
            'jti': secrets.token_urlsafe(16),
            'client_id': client.client_id,
            'scope': scope,
            'token_type': 'access',
            'token_use': 'mail_delegated',
        }
        access_str = _rs256_encode(payload)
        logger.info(
            'OAuth delegated mail token minted (token-exchange) client=%s user_id=%s ttl=%ss',
            client.client_id, user.pk, ttl_seconds,
        )
        return Response({
            'access_token': access_str,
            'issued_token_type': 'urn:ietf:params:oauth:token-type:access_token',
            'token_type': 'Bearer',
            'expires_in': ttl_seconds,
            'scope': scope,
        })


# ───────────────────────────────────────────────────────────────── Userinfo

class UserinfoView(APIView):
    """OIDC-style userinfo endpoint (PLAT-499).

    Accepts both HS256 SimpleJWT tokens (existing clients) and RS256-signed
    OAuth access tokens so OIDC clients such as oauth2-proxy (--profile-url)
    and mail/notes OIDC apps can fetch claims without a 401.
    """
    authentication_classes = [RS256OAuthBearerAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        u = request.user
        claims = _oidc_claims_for_user(u)
        token_claims = request.auth
        if (
            isinstance(token_claims, dict)
            and token_claims.get('token_use') == 'mail_delegated'
        ):
            from .lifecycle import mailbox_address_for_user
            claims['email'] = mailbox_address_for_user(u)
        claims.update({
            'is_staff': getattr(u, 'is_staff', False),
            'is_superuser': getattr(u, 'is_superuser', False),
        })
        return Response(claims)


def _decode_oauth_access_token_for_status(token_str: str) -> dict | None:
    """Decode a shizuha-id OAuth access token for revocation-status checks."""
    if not token_str:
        return None
    try:
        access = AccessToken(token_str)
        return dict(access.payload)
    except Exception:
        pass

    try:
        import jwt as _jwt
        material = get_signing_material()
        payload = _jwt.decode(
            token_str,
            material['public_pem'],
            algorithms=['RS256'],
            options={'verify_aud': False, 'verify_iss': False},
        )
    except Exception:
        return None
    if payload.get('token_type') != 'access':
        return None
    return payload


class OAuthRevocationStatusView(APIView):
    """
    Resource-server liveness check for PLAT-47 access-token cutoffs.

    MCP resource servers already validate JWT signature/expiry locally. They
    call this endpoint with the bearer token so shizuha-id can apply the
    database-backed client-wide and agent-scoped revocation cutoffs without
    exposing cutoff timestamps or webhook-style secrets to the resource server.
    """
    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    def post(self, request):
        payload = _decode_oauth_access_token_for_status(request.data.get('token', ''))
        if payload is None:
            return Response({'active': False, 'token_version': 0})

        client_id = (payload.get('client_id') or '').strip()
        if not client_id:
            # First-party logout revokes only its sid; it intentionally does
            # not bump the account-wide version. Resource servers must consult
            # the same authoritative session/cutoff gates as ID authentication.
            from rest_framework.exceptions import AuthenticationFailed
            from .authentication import _enforce_user_revocation, _session_is_revoked

            user_id = payload.get('user_id')
            if not user_id or not User.objects.filter(pk=user_id, is_active=True).exists():
                return Response({'active': False, 'token_version': 0})
            profile = UserProfile.objects.filter(user_id=user_id).first()
            version = (profile.token_version or 0) if profile else 0
            revoked = _session_is_revoked(user_id, payload.get('sid'))
            try:
                _enforce_user_revocation(
                    profile.access_revoked_before if profile else None,
                    payload.get('iat'), AuthenticationFailed,
                )
            except AuthenticationFailed:
                revoked = True
            # DB failures propagate as errors, never an authoritative allow.
            return Response({'active': not revoked, 'token_version': version})

        try:
            client = OAuthClient.objects.get(client_id=client_id)
        except OAuthClient.DoesNotExist:
            return Response({'active': False, 'token_version': 0})

        revoked = _oauth_token_precedes_client_cutoff(payload, client)
        return Response({'active': not revoked, 'token_version': 0})


class AuthorizedAppsView(APIView):
    """
    List + revoke the current user's authorized OAuth clients.

    GET  /id/api/oauth/authorized-apps         → list distinct clients with
                                                 active (non-revoked, non-
                                                 expired) refresh tokens
    DELETE /id/api/oauth/authorized-apps/<id>  → revoke every active refresh
                                                 for (user, client)
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        now = timezone.now()
        active = (
            IssuedRefreshToken.objects
            .filter(user=request.user, revoked_at__isnull=True, expires_at__gt=now)
            .exclude(jti__in=RevokedToken.objects.values('jti'))
            .select_related('client')
        )
        by_client: dict[str, dict] = {}
        for tok in active:
            key = tok.client.client_id
            agg = by_client.setdefault(key, {
                'client_id': tok.client.client_id,
                'client_name': tok.client.client_name,
                'is_system': tok.client.is_system,
                'scopes': set(),
                'session_count': 0,
                'last_used_at': None,
                'first_authorized_at': None,
            })
            agg['session_count'] += 1
            agg['scopes'].add(tok.scope)
            if not agg['first_authorized_at'] or tok.issued_at < agg['first_authorized_at']:
                agg['first_authorized_at'] = tok.issued_at
            last = tok.last_used_at or tok.issued_at
            if not agg['last_used_at'] or last > agg['last_used_at']:
                agg['last_used_at'] = last
        return Response({
            'apps': [
                {**v, 'scopes': sorted(v['scopes'])}
                for v in by_client.values()
            ],
        })

    def delete(self, request, client_id):
        """Revoke every active refresh token this user holds for `client_id`."""
        now = timezone.now()
        active = IssuedRefreshToken.objects.filter(
            user=request.user, client__client_id=client_id,
            revoked_at__isnull=True, expires_at__gt=now,
        )
        revoked_count = 0
        for tok in active:
            RevokedToken.objects.get_or_create(
                jti=tok.jti,
                defaults={
                    'token_type': 'refresh',
                    'user': request.user,
                    'client': tok.client,
                    'reason': 'user-deauthorize',
                },
            )
            tok.revoked_at = now
            tok.save(update_fields=['revoked_at'])
            revoked_count += 1
        logger.info(
            f"User {request.user.email} deauthorized client={client_id} "
            f"({revoked_count} refresh tokens invalidated)"
        )
        return Response({'revoked': revoked_count})


def _oauth_token_precedes_client_cutoff(token, client: OAuthClient) -> bool:
    """Return True when an OAuth token was minted before client revocation."""
    cutoff = getattr(client, 'access_revoked_before', None)
    issued_at = token.get('iat')
    agent_cutoff = _agent_cutoff_for_token(token, client)
    cutoff = max(
        [candidate for candidate in (cutoff, agent_cutoff) if candidate],
        default=None,
    )
    if not cutoff or not issued_at:
        return False
    try:
        token_iat = datetime.fromtimestamp(int(issued_at), tz=_dt_timezone.utc)
    except (TypeError, ValueError, OSError):
        return True
    return token_iat <= cutoff


def _token_agent_principals(token) -> list[str]:
    """Return non-empty token identity strings that may match revocation agent_id."""
    principals = []
    for claim in ('username', 'email'):
        value = (token.get(claim) or '').strip()
        if value and value not in principals:
            principals.append(value)
    return principals


def _agent_cutoff_for_token(token, client: OAuthClient):
    principals = _token_agent_principals(token)
    if not principals:
        return None
    query = Q()
    for principal in principals:
        query |= Q(agent_id__iexact=principal)
    cutoff = (
        OAuthClientAgentRevocationCutoff.objects
        .filter(client=client)
        .filter(query)
        .order_by('-access_revoked_before')
        .first()
    )
    return getattr(cutoff, 'access_revoked_before', None)


def _actor_identity(request) -> str:
    user = getattr(request, 'user', None)
    if user and getattr(user, 'is_authenticated', False):
        return getattr(user, 'email', '') or getattr(user, 'username', '') or str(user.pk)
    return 'anonymous'


def _actor_has_admin_scope(request) -> bool:
    user = getattr(request, 'user', None)
    if not user or not getattr(user, 'is_authenticated', False):
        return False
    if getattr(user, 'is_superuser', False) or getattr(user, 'is_staff', False):
        return True

    token = getattr(request, 'auth', None)
    if not hasattr(token, 'get'):
        return False
    if token.get('oauth_client_revoke') is True:
        return True
    scope = token.get('scope', '')
    privileged_scopes = {'oauth:revoke', 'admin:oauth-revoke'}
    return bool(privileged_scopes.intersection(str(scope).split()))


def _actor_can_revoke_client(request, client: OAuthClient) -> bool:
    user = getattr(request, 'user', None)
    if not user or not getattr(user, 'is_authenticated', False):
        return False
    if _actor_has_admin_scope(request):
        return True
    token = getattr(request, 'auth', None)
    if hasattr(token, 'get') and token.get('client_id') == client.client_id:
        return True
    return False


def _revoke_refresh_family(*, user, client: OAuthClient, token_family: str,
                           reason: str):
    """DRV-106: revoke every refresh token in a family (and its device session).

    Used on refresh-token replay and device/revoke-all revocation. Revokes the
    IssuedRefreshToken rows, records RFC 7009 RevokedToken entries, and marks
    the bound OAuthDevice inactive so it can no longer refresh.
    """
    if not token_family:
        return 0
    revoked_at = timezone.now()
    family_tokens = IssuedRefreshToken.objects.filter(
        user=user, client=client, token_family=token_family,
    )
    count = 0
    for tok in family_tokens:
        RevokedToken.objects.get_or_create(
            jti=tok.jti,
            defaults={
                'token_type': 'refresh',
                'user': user,
                'client': client,
                'reason': reason[:100],
            },
        )
        if tok.revoked_at is None:
            tok.revoked_at = revoked_at
            tok.save(update_fields=['revoked_at'])
            count += 1
    # Revoke the bound device session(s) for this family.
    device_ids = set(family_tokens.exclude(device__isnull=True)
                     .values_list('device__device_id', flat=True))
    if device_ids:
        OAuthDevice.objects.filter(
            user=user, device_id__in=device_ids, is_active=True,
        ).update(is_active=False, revoked_at=revoked_at)
    return count


def _active_refresh_tokens_for_client(client: OAuthClient, agent_id: str = ''):
    now = timezone.now()
    active = (
        IssuedRefreshToken.objects
        .filter(client=client, revoked_at__isnull=True, expires_at__gt=now)
        .exclude(jti__in=RevokedToken.objects.values('jti'))
        .select_related('user')
    )
    agent_id = (agent_id or '').strip()
    if agent_id:
        active = active.filter(
            Q(user__username__iexact=agent_id) | Q(user__email__iexact=agent_id)
        )
    return active


def _revoke_refresh_tokens_for_client(*, client: OAuthClient, agent_id: str,
                                      reason: str, revoked_at):
    revoked_count = 0
    for tok in _active_refresh_tokens_for_client(client, agent_id):
        RevokedToken.objects.get_or_create(
            jti=tok.jti,
            defaults={
                'token_type': 'refresh',
                'user': tok.user,
                'client': client,
                'reason': reason[:100],
            },
        )
        tok.revoked_at = revoked_at
        tok.save(update_fields=['revoked_at'])
        revoked_count += 1
    return revoked_count


def _authenticate_revoke_actor(request):
    """Authenticate the PLAT-47 client-id revoke branch without changing RFC7009."""
    if getattr(request.user, 'is_authenticated', False):
        return None
    try:
        auth_result = OAuthClientRevocationJWTAuthentication().authenticate(request)
    except Exception as exc:  # noqa: BLE001 - translate auth failures to endpoint contract.
        logger.warning("OAuth client_id revoke authentication failed: %s", exc)
        return Response({'error': 'not_authenticated'}, status=status.HTTP_401_UNAUTHORIZED)
    if auth_result is None:
        return Response({'error': 'not_authenticated'}, status=status.HTTP_401_UNAUTHORIZED)
    request.user, request.auth = auth_result
    return None


class RevokeView(APIView):
    """
    OAuth revocation endpoint.

    Supports both:
      * RFC 7009 `token` + optional `token_type_hint` (public, always 200)
      * PLAT-47 `client_id` + optional `agent_id`/`reason` emergency revocation
        (authenticated admin-scoped service token or self-revoke only)
    """
    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    def post(self, request):
        token_str = request.data.get('token')
        if token_str:
            return self._revoke_token_string(request, token_str)

        client_id = (request.data.get('client_id') or '').strip()
        if client_id:
            return self._revoke_by_client_id(request, client_id)

        return Response({'error': 'invalid_request'}, status=status.HTTP_400_BAD_REQUEST)

    def _revoke_token_string(self, request, token_str: str):
        hint = request.data.get('token_type_hint', '')

        # Try refresh first unless the hint points at access
        attempts = (['access', 'refresh'] if hint == 'access_token'
                    else ['refresh', 'access'])
        for kind in attempts:
            try:
                tok = _decode_oauth_token_for_revocation(token_str, kind)
            except Exception:
                continue
            jti = tok.get('jti')
            if not jti:
                continue
            user_id = tok.get('user_id')
            client_id = tok.get('client_id')
            user = None
            client = None
            if user_id:
                try:
                    user = User.objects.get(pk=user_id)
                except User.DoesNotExist:
                    user = None
            if client_id:
                try:
                    client = OAuthClient.objects.get(client_id=client_id)
                except OAuthClient.DoesNotExist:
                    client = None
            RevokedToken.objects.get_or_create(
                jti=jti,
                defaults={
                    'token_type': kind,
                    'user': user,
                    'client': client,
                    'reason': 'client-revoke',
                },
            )
            if kind == 'refresh':
                IssuedRefreshToken.objects.filter(
                    jti=jti, revoked_at__isnull=True,
                ).update(revoked_at=timezone.now())
            logger.info(f"OAuth token revoked jti={jti} type={kind} user={user_id}")
            break
        # Per RFC 7009, always 200 — never reveal whether token existed.
        return Response(status=status.HTTP_200_OK)

    def _revoke_by_client_id(self, request, client_id: str):
        auth_error = _authenticate_revoke_actor(request)
        if auth_error is not None:
            return auth_error
        if not getattr(request.user, 'is_authenticated', False):
            return Response({'error': 'not_authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            client = OAuthClient.objects.get(client_id=client_id)
        except OAuthClient.DoesNotExist:
            return Response({'error': 'client_not_found'}, status=status.HTTP_404_NOT_FOUND)

        if not _actor_can_revoke_client(request, client):
            return Response({'error': 'forbidden'}, status=status.HTTP_403_FORBIDDEN)

        agent_id = (request.data.get('agent_id') or '').strip()
        if len(agent_id) > 150:
            return Response(
                {
                    'error': 'invalid_request',
                    'error_description': 'agent_id must be 150 characters or fewer',
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        reason = (request.data.get('reason') or 'client-id-revoke').strip()[:100]
        revoked_at = timezone.now()

        # Access-token cutoff: unscoped client revokes use the client-wide
        # cutoff; agent-scoped revokes use a per-agent cutoff so unrelated
        # agents/users under the same client_id are not invalidated.
        if agent_id:
            OAuthClientAgentRevocationCutoff.objects.update_or_create(
                client=client,
                agent_id=agent_id,
                defaults={'access_revoked_before': revoked_at},
            )
        else:
            client.access_revoked_before = revoked_at
            client.save(update_fields=['access_revoked_before'])

        revoked_count = _revoke_refresh_tokens_for_client(
            client=client,
            agent_id=agent_id,
            reason=reason,
            revoked_at=revoked_at,
        )
        revoked_at_iso = revoked_at.isoformat()
        emit_oauth_client_revocation(
            revoked_client_id=client.client_id,
            revoked_agent_id=agent_id or None,
            revoker_identity=_actor_identity(request),
            reason=reason,
            revoked_tokens=revoked_count,
            revoked_at=revoked_at_iso,
        )
        logger.warning(
            "OAuth client_id revoked client=%s agent_id=%s revoked_tokens=%s revoker=%s",
            client.client_id,
            agent_id or '-',
            revoked_count,
            _actor_identity(request),
        )
        return Response({
            'revoked_tokens': revoked_count,
            'revoked_at': revoked_at_iso,
        }, status=status.HTTP_200_OK)


class DeviceRegistryView(APIView):
    """
    DRV-106: server-bound device registry for the Drive Desktop client.

    Actions (POST /api/oauth/devices/):
      * register      — register/heartbeat a device (device_id, name, os, build)
      * revoke        — revoke one device's refresh family (logout on this device)
      * revoke-all    — sign out every device (optionally except the current one)

    Authentication: a Drive Desktop OAuth access token (Bearer) or an
    authenticated user session. The device is bound to the refresh family
    issued at authorization-code grant time.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        action = (request.data.get('action') or '').strip()
        if action == 'register':
            return self._register(request)
        if action == 'revoke':
            return self._revoke(request)
        if action == 'revoke-all':
            return self._revoke_all(request)
        return Response(
            {'error': 'invalid_request',
             'error_description': 'action must be register, revoke, or revoke-all'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    def _register(self, request):
        device_id = (request.data.get('device_id') or '').strip()
        if not device_id:
            return Response(
                {'error': 'invalid_request', 'error_description': 'device_id required'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if len(device_id) > 255:
            return Response(
                {'error': 'invalid_request', 'error_description': 'device_id too long'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        client = None
        auth = getattr(request, 'auth', None)
        if hasattr(auth, 'get') and auth.get('client_id'):
            try:
                client = OAuthClient.objects.get(client_id=auth['client_id'])
            except OAuthClient.DoesNotExist:
                client = None
        device, created = OAuthDevice.objects.update_or_create(
            user=request.user,
            device_id=device_id,
            defaults={
                'client': client,
                'name': (request.data.get('device_name') or '')[:255],
                'os': (request.data.get('device_os') or '')[:100],
                'build': (request.data.get('device_build') or '')[:100],
                'last_seen_at': timezone.now(),
                'is_active': True,
                'revoked_at': None,
            },
        )
        return Response({
            'device_id': device.device_id,
            'registered': created,
            'is_active': device.is_active,
        }, status=status.HTTP_200_OK)

    def _revoke(self, request):
        device_id = (request.data.get('device_id') or '').strip()
        if not device_id:
            return Response(
                {'error': 'invalid_request', 'error_description': 'device_id required'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        device = OAuthDevice.objects.filter(
            user=request.user, device_id=device_id,
        ).first()
        if device is None:
            return Response(
                {'error': 'device_not_found'}, status=status.HTTP_404_NOT_FOUND,
            )
        # Revoke every refresh family bound to this device.
        family_ids = set(
            IssuedRefreshToken.objects
            .filter(user=request.user, device=device)
            .values_list('token_family', flat=True)
        )
        revoked = 0
        for family in family_ids:
            if not family:
                continue
            revoked += _revoke_refresh_family(
                user=request.user, client=device.client, token_family=family,
                reason='device revoke',
            )
        device.is_active = False
        device.revoked_at = timezone.now()
        device.save(update_fields=['is_active', 'revoked_at', 'updated_at'])
        logger.info(
            f"OAuth device revoked user={request.user.email} device={device_id} "
            f"families={len(family_ids)}"
        )
        return Response({
            'device_id': device_id,
            'revoked': True,
            'revoked_families': len(family_ids),
            'revoked_tokens': revoked,
        }, status=status.HTTP_200_OK)

    def _revoke_all(self, request):
        exclude_current = bool(request.data.get('exclude_current'))
        current_device_id = (request.data.get('device_id') or '').strip()
        devices = OAuthDevice.objects.filter(
            user=request.user, is_active=True,
        )
        if exclude_current and current_device_id:
            devices = devices.exclude(device_id=current_device_id)
        total_families = 0
        total_tokens = 0
        for device in devices:
            family_ids = set(
                IssuedRefreshToken.objects
                .filter(user=request.user, device=device)
                .values_list('token_family', flat=True)
            )
            for family in family_ids:
                if not family:
                    continue
                total_tokens += _revoke_refresh_family(
                    user=request.user, client=device.client, token_family=family,
                    reason='revoke-all',
                )
            total_families += len(family_ids)
            device.is_active = False
            device.revoked_at = timezone.now()
            device.save(update_fields=['is_active', 'revoked_at', 'updated_at'])
        logger.info(
            f"OAuth revoke-all user={request.user.email} "
            f"devices={devices.count()} families={total_families}"
        )
        return Response({
            'revoked_devices': devices.count(),
            'revoked_families': total_families,
            'revoked_tokens': total_tokens,
        }, status=status.HTTP_200_OK)
