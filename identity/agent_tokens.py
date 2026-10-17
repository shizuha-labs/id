"""
RS256 platform token classes — PLAT-255 / PLAT-1179.

All first-party Shizuha principals receive RS256-signed JWTs so that
secret-less verifiers can validate tokens via the existing
/.well-known/jwks.json endpoint without holding the HS256 signing secret, which
would allow token forgery.

Agent broker-relay tokens retain their narrow `aud='shizuha:broker-relay'`.
Human/browser tokens use `aud='*'`, which existing first-party services treat as
the wildcard audience while they complete service-by-service audience
enforcement.

Key properties of RS256 tokens:
  - alg=RS256, kid in header (JWKS discovery)
  - canonical configured `iss` on every newly minted token
  - human/browser aud='*'; agent aud='shizuha:broker-relay'
  - Signed with the oauth_keys RSA private key (same key exposed via JWKS)
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import jwt as _pyjwt
from rest_framework_simplejwt.backends import TokenBackend
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

BROKER_RELAY_AUD = 'shizuha:broker-relay'

_AGENT_BACKEND: '_AgentTokenBackend | None' = None
_PLATFORM_BACKEND: '_AgentTokenBackend | None' = None


def _get_agent_backend() -> '_AgentTokenBackend':
    """Lazy singleton — defer key loading until first token mint."""
    global _AGENT_BACKEND
    if _AGENT_BACKEND is None:
        from django.conf import settings
        from .oauth_keys import get_signing_material
        m = get_signing_material()
        _AGENT_BACKEND = _AgentTokenBackend(
            private_pem=m['private_pem'],
            public_pem=m['public_pem'],
            kid=m['kid'],
            audience=BROKER_RELAY_AUD,
            issuer=settings.OAUTH_ISSUER_URL,
        )
    return _AGENT_BACKEND


def _get_platform_backend() -> '_AgentTokenBackend':
    """Lazy singleton for first-party human/browser tokens (aud='*')."""
    global _PLATFORM_BACKEND
    if _PLATFORM_BACKEND is None:
        from django.conf import settings
        from .oauth_keys import get_signing_material
        m = get_signing_material()
        _PLATFORM_BACKEND = _AgentTokenBackend(
            private_pem=m['private_pem'],
            public_pem=m['public_pem'],
            kid=m['kid'],
            audience='*',
            issuer=settings.OAUTH_ISSUER_URL,
        )
    return _PLATFORM_BACKEND


class _AgentTokenBackend(TokenBackend):
    """RS256 token backend that stamps `kid` in the JWT header.

    `kid` is required so JWKS-based verifiers (e.g. the broker sidecar) can
    select the correct public key from the JWKS document without guessing.

    Agent tokens use BROKER_RELAY_AUD — the broker validates this claim per
    ADR-PLAT-002 §5.2. Human/browser platform tokens use `aud='*'` until Phase C
    service-by-service audience enforcement lands. The issuer is stamped on
    every newly encoded token but is deliberately not passed to TokenBackend's
    decoder yet: issuer-less RS256 refresh tokens minted before BKS-167 must
    remain refreshable into an issuer-bearing pair during the rollout.
    """

    def __init__(
        self,
        private_pem: str,
        public_pem: str,
        kid: str,
        audience: str,
        issuer: str,
    ) -> None:
        super().__init__(
            algorithm='RS256',
            signing_key=private_pem,
            verifying_key=public_pem,
            audience=audience,
        )
        self._kid = kid
        self._audience = audience
        self._issuer = issuer.rstrip('/')

    def encode(self, payload: dict) -> str:
        jwt_payload = payload.copy()
        jwt_payload['iss'] = self._issuer
        jwt_payload['aud'] = self._audience

        token = _pyjwt.encode(
            jwt_payload,
            self.signing_key,
            algorithm='RS256',
            headers={'kid': self._kid},
        )
        # PyJWT < 2 returns bytes; >= 2 returns str.
        return token.decode('utf-8') if isinstance(token, bytes) else token


class AgentAccessToken(AccessToken):
    """RS256 access token for agent accounts."""

    def get_token_backend(self) -> _AgentTokenBackend:  # type: ignore[override]
        return _get_agent_backend()


class AgentRefreshToken(RefreshToken):
    """RS256 refresh token for agent accounts. Issues AgentAccessToken on refresh."""

    access_token_class = AgentAccessToken  # type: ignore[assignment]

    def get_token_backend(self) -> _AgentTokenBackend:  # type: ignore[override]
        return _get_agent_backend()


class PlatformAccessToken(AccessToken):
    """RS256 access token for first-party human/browser users."""

    def get_token_backend(self) -> _AgentTokenBackend:  # type: ignore[override]
        return _get_platform_backend()


class PlatformRefreshToken(RefreshToken):
    """RS256 refresh token for first-party human/browser users."""

    access_token_class = PlatformAccessToken  # type: ignore[assignment]

    def get_token_backend(self) -> _AgentTokenBackend:  # type: ignore[override]
        return _get_platform_backend()
