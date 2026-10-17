"""Authentication helpers for shizuha-id.

PLAT-47 adds a client-level emergency revoke switch for OAuth access tokens.
Regular user/service tokens do not carry ``client_id`` and continue down the
normal SimpleJWT path; OAuth access tokens do, so this authenticator rejects
pre-cutoff tokens before DRF resolves the request user.

PLAT-499 adds RS256OAuthBearerAuthentication — a two-path authenticator that
accepts both HS256 SimpleJWT tokens AND RS256-signed OAuth access tokens.
Used by UserinfoView so OIDC clients (oauth2-proxy --profile-url, mail, notes)
that received an RS256 access token can call the userinfo endpoint.
"""
from __future__ import annotations

from datetime import datetime, timezone as dt_timezone

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db.models import Q
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed as DRFAuthFailed
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import AuthenticationFailed

from .models import OAuthClient, OAuthClientAgentRevocationCutoff

User = get_user_model()

# ID-13: the cutoff is read on EVERY authenticated request, so cache it to avoid a
# per-request UserProfile DB hit. The cache is an optimisation layered over the
# authoritative DB, NOT the source of truth:
#   - cache HIT  -> use it.
#   - cache MISS or cache backend DOWN -> fall through to the DB (which is itself
#     fail-closed: a DB error propagates as a 401, never an allow-through).
#   - the revoke path invalidates this cache at the outer transaction's commit,
#     so rolled-back cutoffs never become authority and late callbacks cannot
#     overwrite a newer committed cutoff with an older captured timestamp.
# `_NO_CUTOFF_SENTINEL` lets us cache the (common) "no cutoff" answer too — without
# it every normal-user request would still hit the DB. With a SHARED cache backend
# (Redis/memcached) commit invalidation is effective fleet-wide immediately;
# with the default per-process LocMemCache, a worker that cached "no cutoff" before a
# logout on ANOTHER worker is bounded by ID13_ACCESS_CUTOFF_CACHE_TTL (default 60s),
# still a vast improvement over the full access-token TTL the cutoff replaces.
_ACCESS_CUTOFF_CACHE_PREFIX = 'id13:access_cutoff:'
_NO_CUTOFF_SENTINEL = 'none'
_SESSION_REVOCATION_CACHE_PREFIX = 'id70:revoked_session:'


def _access_cutoff_cache_key(user_id):
    return f'{_ACCESS_CUTOFF_CACHE_PREFIX}{user_id}'


def _access_cutoff_cache_ttl():
    return int(getattr(settings, 'ID13_ACCESS_CUTOFF_CACHE_TTL', 60))


def prime_user_access_cutoff_cache(user_id, cutoff):
    """Write through an already-authoritative cutoff (legacy compatibility API).

    Transactional revocation uses commit-time invalidation instead; publishing a
    captured cutoff before outer commit would leak rolled-back authority.
    """
    if not user_id:
        return
    try:
        cache.set(
            _access_cutoff_cache_key(user_id),
            cutoff if cutoff is not None else _NO_CUTOFF_SENTINEL,
            _access_cutoff_cache_ttl(),
        )
    except Exception:
        pass


def invalidate_user_access_cutoff_cache(user_id):
    """Discard cached authority after commit; the next read loads the current DB.

    Invalidation carries no timestamp, so an earlier transaction's delayed
    callback cannot replace a later committed cutoff with an older value.
    Cache failures retain the existing best-effort cache/authoritative DB read
    contract; no post-commit exception can misreport a durable revocation.
    """
    if not user_id:
        return
    try:
        cache.delete(_access_cutoff_cache_key(user_id))
    except Exception:
        pass


def _user_access_cutoff(user_id):
    """ID-13: the user's access-token revocation cutoff (UserProfile.access_revoked_before).

    Cache-backed with DB fallback. Returns the cutoff datetime, or None when there
    is no user_id / no profile / no cutoff set. FAIL-CLOSED: a cache miss or a cache
    backend error falls through to the DB, and a DB error propagates (→ 401) rather
    than allowing the token through.
    """
    if not user_id:
        return None
    key = _access_cutoff_cache_key(user_id)
    try:
        cached = cache.get(key)
    except Exception:
        cached = None  # cache backend down → fall through to the authoritative DB
    if cached is not None:
        return None if cached == _NO_CUTOFF_SENTINEL else cached
    # Cache miss (or cache down): authoritative DB read, then populate the cache.
    from .models import UserProfile
    cutoff = (
        UserProfile.objects
        .filter(user_id=user_id)
        .values_list('access_revoked_before', flat=True)
        .first()
    )
    try:
        cache.set(
            key,
            cutoff if cutoff is not None else _NO_CUTOFF_SENTINEL,
            _access_cutoff_cache_ttl(),
        )
    except Exception:
        pass  # caching is best-effort; the DB read above is authoritative
    return cutoff


def _enforce_user_revocation(revoked_before, iat_claim, exc_class):
    """ID-13: reject a user access token issued at/before the user's cutoff.

    FAIL-CLOSED: when a cutoff IS set, a missing or unparseable ``iat`` is
    rejected (we cannot prove the token post-dates the revocation). No cutoff →
    no-op (normal users are unaffected). Mirrors the OAuthClient cutoff compare.
    """
    if not revoked_before:
        return
    if iat_claim is None:
        raise exc_class('Access token missing iat claim.')
    try:
        token_iat = datetime.fromtimestamp(
            iat_claim if isinstance(iat_claim, (int, float)) else int(iat_claim),
            tz=dt_timezone.utc,
        )
    except (TypeError, ValueError) as exc:
        raise exc_class('Access token has invalid iat.') from exc
    if token_iat <= revoked_before:
        raise exc_class('User access token revoked.')


def _session_revocation_cache_key(user_id, sid):
    return f'{_SESSION_REVOCATION_CACHE_PREFIX}{user_id}:{sid}'


def _session_revocation_cache_ttl():
    # Keep positive entries beyond the normal 30-day refresh lifetime. Negative
    # answers are deliberately NOT cached: the authoritative DB is consulted on
    # every still-valid session, so a logout on another worker is immediate even
    # when the configured cache backend is process-local.
    return int(getattr(settings, 'ID70_SESSION_REVOCATION_CACHE_TTL', 31 * 24 * 60 * 60))


def prime_session_revocation_cache(user_id, sid):
    """Write through a positive session-revocation result (best effort)."""
    if not user_id or not sid:
        return
    try:
        cache.set(
            _session_revocation_cache_key(user_id, sid),
            True,
            _session_revocation_cache_ttl(),
        )
    except Exception:
        pass


def _session_is_revoked(user_id, sid):
    """Return the authoritative revocation state for one stable ``sid``.

    Cache hits can answer only "revoked". A miss or cache failure always falls
    back to the indexed DB row; DB errors propagate so validation fails closed.
    Legacy tokens without ``sid`` are governed by the existing account cutoff.

    ID-70 P1 #1 (fail-closed): a sid that was never issued — no ``ActiveSession``
    allow-list row — is NOT a valid session and is treated as revoked. Every
    sid minted by this service records an ``ActiveSession`` row, so only
    unknown/expired/stale sids hit the fail-closed branch.
    """
    sid = str(sid or '').strip()
    if not user_id or not sid:
        return False
    key = _session_revocation_cache_key(user_id, sid)
    try:
        if cache.get(key) is True:
            return True
    except Exception:
        pass
    from .models import RevokedSession, ActiveSession
    revoked = RevokedSession.objects.filter(user_id=user_id, sid=sid).exists()
    if revoked:
        prime_session_revocation_cache(user_id, sid)
        return True
    # Fail closed on an unknown sid: no allow-list row means this sid was never
    # issued by this service, so it must not be accepted as an active session.
    return not ActiveSession.objects.filter(user_id=user_id, sid=sid).exists()


def _enforce_session_revocation(user_id, sid, exc_class):
    if _session_is_revoked(user_id, sid):
        raise exc_class('Session revoked.')


class OAuthClientRevocationJWTAuthentication(JWTAuthentication):
    """SimpleJWT auth with OAuth-client revocation cutoff enforcement."""

    def get_validated_token(self, raw_token):
        validated = super().get_validated_token(raw_token)

        # ID-13: user-level access-token revocation cutoff (set on logout /
        # password-change). Enforced for EVERY access token carrying a user_id —
        # with or without a client_id — so a logged-out user's token is rejected
        # on the next request, not after its full TTL.
        _enforce_user_revocation(
            _user_access_cutoff(validated.get('user_id')),
            validated.get('iat'),
            AuthenticationFailed,
        )
        _enforce_session_revocation(
            validated.get('user_id'),
            validated.get('sid'),
            AuthenticationFailed,
        )

        client_id = validated.get('client_id')
        if not client_id:
            return validated

        try:
            client = OAuthClient.objects.only('client_id', 'access_revoked_before').get(
                client_id=client_id
            )
        except OAuthClient.DoesNotExist as exc:
            raise AuthenticationFailed('OAuth client revoked or unknown') from exc

        cutoff = self._effective_cutoff(validated, client)
        issued_at = validated.get('iat')
        if cutoff and issued_at:
            if isinstance(issued_at, (int, float)):
                token_iat = datetime.fromtimestamp(issued_at, tz=dt_timezone.utc)
            else:
                try:
                    token_iat = datetime.fromtimestamp(int(issued_at), tz=dt_timezone.utc)
                except (TypeError, ValueError) as exc:
                    raise AuthenticationFailed('OAuth token missing valid iat') from exc
            if token_iat <= cutoff:
                raise AuthenticationFailed('OAuth client access token revoked')

        return validated

    def _effective_cutoff(self, token, client):
        cutoffs = [
            candidate
            for candidate in (
                client.access_revoked_before,
                self._agent_cutoff(token, client),
            )
            if candidate
        ]
        return max(cutoffs, default=None)

    def _agent_cutoff(self, token, client):
        query = Q()
        for claim in ('username', 'email'):
            value = (token.get(claim) or '').strip()
            if value:
                query |= Q(agent_id__iexact=value)
        if not query:
            return None
        cutoff = (
            OAuthClientAgentRevocationCutoff.objects
            .filter(client=client)
            .filter(query)
            .order_by('-access_revoked_before')
            .first()
        )
        return getattr(cutoff, 'access_revoked_before', None)


def _verify_rs256_access_token(raw_token, resolve_active_user):
    """Verify an RS256 shizuha-id access token → ``(user, payload)``.

    Single source of truth for the RS256 path shared by
    RS256OAuthBearerAuthentication (userinfo, all verbs) and the CTX-492
    UserView-scoped composite (GET/HEAD read bridge). Enforces signature,
    access-token type, is_active, and BOTH the user-level (ID-13) and
    client-level (PLAT-47/PLAT-499) revocation cutoffs. Raises DRFAuthFailed on
    any failure. ``verify_aud/verify_iss`` disabled intentionally: shizuha-id is
    a single self-issued IDP — issuer/audience are implied by the RS256
    public-key signature.
    """
    try:
        import jwt as _jwt
        from .oauth_keys import get_signing_material
        material = get_signing_material()
        payload = _jwt.decode(
            raw_token,
            material['public_pem'],
            algorithms=['RS256'],
            options={'verify_aud': False, 'verify_iss': False},
        )
    except Exception:
        raise DRFAuthFailed('Token is invalid or expired.')

    if payload.get('token_type') != 'access':
        raise DRFAuthFailed('Token is not an access token.')

    user = resolve_active_user(payload.get('user_id'))

    _enforce_user_revocation(
        _user_access_cutoff(user.id),
        payload.get('iat'),
        DRFAuthFailed,
    )
    _enforce_session_revocation(user.id, payload.get('sid'), DRFAuthFailed)

    client_id = payload.get('client_id')
    if client_id:
        try:
            client = OAuthClient.objects.only('client_id', 'access_revoked_before').get(
                client_id=client_id
            )
        except OAuthClient.DoesNotExist:
            raise DRFAuthFailed('OAuth client revoked or unknown.')
        _rev = OAuthClientRevocationJWTAuthentication()
        cutoff = _rev._effective_cutoff(payload, client)
        if cutoff:
            iat = payload.get('iat')
            if iat is None:
                raise DRFAuthFailed('Token missing iat claim.')
            token_iat = datetime.fromtimestamp(iat, tz=dt_timezone.utc)
            if token_iat <= cutoff:
                raise DRFAuthFailed('Token has been revoked.')

    return (user, payload)


class UserViewScopedCompositeAuthentication(BaseAuthentication):
    """CTX-492 / CTX-497 v3 (Security-reviewed by Ren): a single method-aware
    composite authenticator for ``UserView`` (``/id/api/auth/user/``).

    - HS256 SimpleJWT (ALL verbs): if the raw token validates as an HS256
      SimpleJWT it is definitively ours (user + client revocation already
      enforced by OAuthClientRevocationJWTAuthentication) → authenticate.
    - RS256 read bridge (GET/HEAD ONLY): only if HS256 did not match AND the
      request is a safe read AND the fail-closed positive predicate holds →
      RS256-verify and authenticate the caller's OWN record. PATCH and every
      other verb NEVER reach the RS256 path, so a broad/delegated RS256 token
      can never mutate an account.
    - Otherwise → return None (DRF ``IsAuthenticated`` → 401/403).

    A single class (not a two-authenticator list): the default
    OAuthClientRevocationJWTAuthentication raises ``InvalidToken`` on an RS256
    token, and DRF aborts on the first authenticator that raises — which would
    shadow a second RS256 authenticator entirely.
    """

    #: Safe read methods eligible for the RS256 bridge. OPTIONS is excluded (no
    #: authenticated consumer; CORS preflights are unauthenticated).
    _RS256_READ_METHODS = frozenset({'GET', 'HEAD'})

    @staticmethod
    def _rs256_read_predicate(payload) -> bool:
        """Fail-closed positive allow predicate (CTX-497 v3 §2).

        ALL must hold: access token; ``token_use`` absent or exactly
        ``'sso_general'`` (any other value, incl. ``mail_delegated`` and any
        future delegated family, is denied); ``client_id`` in the bounded
        config allowlist. Unknown/absent client → deny.
        """
        if payload.get('token_type') != 'access':
            return False
        token_use = payload.get('token_use')
        if token_use not in (None, 'sso_general'):
            return False
        allowed = set(getattr(settings, 'RS256_USERINFO_ALLOWED_CLIENT_IDS', ()) or ())
        client_id = payload.get('client_id')
        if not client_id or client_id not in allowed:
            return False
        return True

    def authenticate(self, request):
        auth = get_authorization_header(request).split()
        if not auth or auth[0].lower() != b'bearer':
            return None
        if len(auth) != 2:
            raise DRFAuthFailed('Invalid token header.')
        raw_token = auth[1]

        # Path 1 — HS256 SimpleJWT (all verbs). Definitively ours if it validates.
        try:
            validated = OAuthClientRevocationJWTAuthentication().get_validated_token(raw_token)
        except Exception:
            validated = None
        if validated is not None:
            return (
                RS256OAuthBearerAuthentication._resolve_active_user(validated.get('user_id')),
                validated,
            )

        # Path 2 — RS256 read bridge: GET/HEAD only. A non-safe verb (e.g. PATCH)
        # never authenticates via RS256 → None → the mutation is rejected.
        if (request.method or '').upper() not in self._RS256_READ_METHODS:
            return None

        # Full RS256 verification (signature + is_active + user/client revocation)
        # raises on hard failures (bad signature, revoked → 401). A valid token
        # that fails the positive predicate (delegated/unknown client) is denied
        # softly → None → 403, so it is never authenticated as the user.
        user, payload = _verify_rs256_access_token(
            raw_token, RS256OAuthBearerAuthentication._resolve_active_user
        )
        if not self._rs256_read_predicate(payload):
            return None
        return (user, payload)


class RS256OAuthBearerAuthentication(BaseAuthentication):
    """Accept HS256 SimpleJWT OR RS256 OAuth access tokens on the userinfo endpoint.

    Path 1 — HS256 SimpleJWT: delegates to OAuthClientRevocationJWTAuthentication
              so existing revocation cutoffs are still enforced.
    Path 2 — RS256 JWT: validates against the shizuha-id public key (JWKS) and
              returns the user identified by the ``user_id`` claim.

    Returns None (unauthenticated, let other backends try) when the request
    carries no Bearer token at all. Raises AuthenticationFailed for a malformed
    or invalid token so the caller gets 401 rather than 403.
    """

    @staticmethod
    def _resolve_active_user(user_id):
        """Resolve the token's user and enforce is_active.

        PLAT-672: an inactive/disabled user must NOT authenticate, matching
        SimpleJWT ``JWTAuthentication.get_user`` (which the HS256 default enforces).
        This is required before this dual-verify class can become the platform-wide
        default authenticator — otherwise a disabled user's still-valid token would
        keep working until natural expiry.
        """
        if not user_id:
            raise DRFAuthFailed('Token missing user_id claim.')
        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist as exc:
            raise DRFAuthFailed('User not found.') from exc
        if not getattr(user, 'is_active', True):
            raise DRFAuthFailed('User is inactive.')
        return user

    def authenticate(self, request):
        auth = get_authorization_header(request).split()
        if not auth or auth[0].lower() != b'bearer':
            return None
        if len(auth) != 2:
            raise DRFAuthFailed('Invalid token header.')

        raw_token = auth[1]

        # Path 1: HS256 SimpleJWT (with revocation enforcement). If the token is a
        # valid HS256 SimpleJWT, it is DEFINITIVELY ours — resolve the (active) user
        # and return; do NOT fall through to the RS256 path (which would fail on an
        # HS256 token anyway). A validation failure here just means "not an HS256
        # token" → try RS256 next.
        validated = None
        try:
            validated = OAuthClientRevocationJWTAuthentication().get_validated_token(raw_token)
        except Exception:
            validated = None
        if validated is not None:
            return (self._resolve_active_user(validated.get('user_id')), validated)

        # Path 2: RS256 JWT signed by the shizuha-id keypair.
        return _verify_rs256_access_token(raw_token, self._resolve_active_user)
