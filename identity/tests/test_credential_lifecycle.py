"""Credential-lifecycle invariant tests (PLAT-8618).

Pins three authentication-plane invariants against the real oauth_views /
verifier paths (reporter-confirmed surface: shizuha-labs/id):

  1. Expiry — an expired RS256 access token is rejected end-to-end through
     the MCP resource-server verifier (real signature + expiry validation,
     only the JWKS transport stubbed), and refresh-token expiry is
     distinguished from replay: expiry fails closed WITHOUT the fail-closed
     family-revocation side effect that replay carries.
  2. Revocation propagation — after a DRV-106 family revocation every
     descendant is rejected at the token endpoint, and a PLAT-47 client
     revocation propagates to the resource side (revocation-status endpoint
     verdict + ShizuhaTokenVerifier decision), with post-revocation mints
     unaffected.
  3. Rotation — rotating a refresh token invalidates the consumed token and
     preserves grants (scope, client, subject, family) across generations.

No production code changes.
"""
import asyncio
import sys
import time
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIRequestFactory, force_authenticate

from identity import oauth_keys, oauth_views
from identity.models import IssuedRefreshToken, OAuthClient, RevokedToken
from identity.oauth_views import (
    OAuthRevocationStatusView,
    RevokeView,
    TokenView,
    _mint_tokens,
)

User = get_user_model()

# The MCP resource-server verifier lives in mcp-server/base.py (imported as
# ``base`` by the existing verifier tests).
_MCP_DIR = str(Path(__file__).resolve().parents[2] / "mcp-server")
if _MCP_DIR not in sys.path:
    sys.path.insert(0, _MCP_DIR)
import base as mcp_base  # noqa: E402

ISSUER = "https://id.example"
SCOPE = "drive:files.read profile"

_projection_patcher = None


def setUpModule():
    global _projection_patcher
    _projection_patcher = mock.patch(
        "identity.oauth_views._fetch_membership_projection",
        return_value=({}, [], {}),
    )
    _projection_patcher.start()


def tearDownModule():
    _projection_patcher.stop()


def _make_client(client_id="lifecycle-client"):
    return OAuthClient.objects.create(
        client_id=client_id,
        client_name="Credential Lifecycle Test Client",
        redirect_uris=["http://127.0.0.1/callback"],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope=SCOPE,
        client_type=OAuthClient.CLIENT_TYPE_PUBLIC,
    )


def _rs256_decode(token_str: str) -> dict:
    """Decode an RS256 OAuth token with the real public key (exp verified)."""
    return pyjwt.decode(
        token_str,
        oauth_keys.get_signing_material()["public_pem"],
        algorithms=["RS256"],
        options={"verify_aud": False},
    )


def _resign_with_exp(token_str: str, exp: int) -> str:
    """Re-encode a token verbatim except for ``exp``, with the real key."""
    payload = _rs256_decode(token_str)
    payload["exp"] = exp
    return oauth_views._rs256_encode(payload)


class _RealKeyJwksClient:
    """JWKS transport stub that serves the REAL ID signing public key.

    Only the network fetch is stubbed; signature and expiry validation in
    ``ShizuhaTokenVerifier._decode`` run for real.
    """

    def __init__(self, url):
        self.url = url

    def get_signing_key_from_jwt(self, token):
        pem = oauth_keys.get_signing_material()["public_pem"]
        if isinstance(pem, str):
            pem = pem.encode("ascii")
        public_key = serialization.load_pem_public_key(pem)
        return SimpleNamespace(key=public_key)


class CredentialLifecycleTestMixin(TestCase):
    def setUp(self):
        self.client_obj = _make_client()
        self.user = User.objects.create_user(
            username="lifecycle", email="lifecycle@example.com", password="x",
        )
        self.factory = APIRequestFactory()

    def _mint(self, family="fam-lifecycle"):
        return _mint_tokens(
            self.user, self.client_obj, SCOPE, ISSUER,
            user_agent="test", token_family=family,
        )

    def _refresh(self, refresh_token):
        req = self.factory.post(
            "/api/oauth/token/",
            {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": self.client_obj.client_id,
            },
            format="json",
        )
        return TokenView.as_view()(req)

    def _revocation_status(self, access_token):
        req = self.factory.post(
            "/api/oauth/revocation-status/",
            {"token": access_token},
            format="json",
        )
        return OAuthRevocationStatusView.as_view()(req)

    def _verifier(self):
        return mcp_base.ShizuhaTokenVerifier("lifecycle-test", ISSUER)

    def _verify(self, verifier, access_token):
        with mock.patch("jwt.PyJWKClient", _RealKeyJwksClient):
            return asyncio.run(verifier.verify_token(access_token))

    def _family_jtis(self, family):
        return list(
            IssuedRefreshToken.objects.filter(
                user=self.user, client=self.client_obj, token_family=family,
            ).values_list("jti", flat=True)
        )


class ExpiredAccessTokenTests(CredentialLifecycleTestMixin):
    def test_expired_access_token_rejected_end_to_end_through_verifier(self):
        """Invariant 1a: real RS256 signature + expiry validation at the
        resource-server verifier rejects an expired access token (a fresh
        control token from the same mint authenticates)."""
        tokens = self._mint()
        verifier = self._verifier()

        # Control: the fresh token authenticates (revocation check stubbed
        # not-revoked; signature/expiry validation is real).
        with mock.patch.object(
            mcp_base.ShizuhaTokenVerifier, "_oauth_token_revoked",
            new=mock.AsyncMock(return_value=False),
        ):
            result = self._verify(verifier, tokens["access_token"])
        self.assertIsNotNone(result)
        self.assertEqual(result.client_id, self.client_obj.client_id)

        # Same payload, real signature, exp in the past → rejected.
        expired = _resign_with_exp(
            tokens["access_token"], int(time.time()) - 60,
        )
        result = self._verify(verifier, expired)
        self.assertIsNone(result)


class RefreshExpiryVsReplayTests(CredentialLifecycleTestMixin):
    def test_expired_refresh_fails_closed_without_family_revocation(self):
        """Invariant 1b: refresh-token EXPIRY is rejected as invalid_grant and
        leaves the family intact — unlike REPLAY, which revokes the whole
        family (DRV-106 fail-closed). The two failure modes are distinct."""
        # Expiry leg: expired refresh token → invalid_grant, family intact.
        tokens = self._mint(family="fam-expiry")
        expired_refresh = _resign_with_exp(
            tokens["refresh_token"], int(time.time()) - 60,
        )
        resp = self._refresh(expired_refresh)
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.data["error"], "invalid_grant")
        for jti in self._family_jtis("fam-expiry"):
            self.assertTrue(
                IssuedRefreshToken.objects.filter(
                    jti=jti, revoked_at__isnull=True,
                ).exists(),
                f"expiry must not revoke family token {jti}",
            )
            self.assertFalse(
                RevokedToken.objects.filter(jti=jti).exists(),
                f"expiry must not record RevokedToken for {jti}",
            )

        # Replay leg (contrast): consumed token replay → family revoked.
        tokens = self._mint(family="fam-replay")
        r1 = tokens["refresh_token"]
        self.assertEqual(self._refresh(r1).status_code, 200)
        resp = self._refresh(r1)
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.data["error"], "invalid_grant")
        self.assertFalse(
            IssuedRefreshToken.objects.filter(
                user=self.user, client=self.client_obj,
                token_family="fam-replay", revoked_at__isnull=True,
            ).exists(),
            "replay must revoke the whole family (DRV-106)",
        )


class FamilyRevocationPropagationTests(CredentialLifecycleTestMixin):
    def test_family_revocation_rejects_every_descendant_at_token_endpoint(self):
        """Invariant 2a: after a replay-triggered family revocation, the
        previously-valid descendant is also rejected ('token revoked') — no
        parallel valid descendant survives (DRV-106)."""
        tokens = self._mint(family="fam-prop")
        r1 = tokens["refresh_token"]
        resp = self._refresh(r1)
        self.assertEqual(resp.status_code, 200)
        r2 = resp.data["refresh_token"]

        # Replay the consumed r1 → whole family (including r2) revoked.
        self.assertEqual(self._refresh(r1).status_code, 400)

        # The descendant r2 was valid a moment ago; it must now be rejected.
        resp = self._refresh(r2)
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.data["error"], "invalid_grant")
        self.assertIn("revoked", resp.data["error_description"])
        for jti in self._family_jtis("fam-prop"):
            self.assertTrue(
                RevokedToken.objects.filter(jti=jti).exists(),
                f"family revocation must record RevokedToken for {jti}",
            )


class ClientRevocationResourceSideTests(CredentialLifecycleTestMixin):
    def _revoke_client(self):
        admin = User.objects.create_user(
            username="revoker", email="revoker@example.com", password="x",
            is_superuser=True,
        )
        req = self.factory.post(
            "/api/oauth/revoke/",
            {"client_id": self.client_obj.client_id, "reason": "lifecycle-test"},
            format="json",
        )
        force_authenticate(req, user=admin)
        return RevokeView.as_view()(req)

    def _verdict_bridge(self, verdicts):
        """Feed the verifier the REAL revocation-status verdicts.

        ``verdicts`` maps access-token string → ``active`` as returned by the
        real OAuthRevocationStatusView (asserted separately above). The
        network hop is removed because sqlite test transactions are not
        visible to the worker thread the real fetch would use; the verdict →
        accept/reject decision of the verifier is exercised for real.
        """

        async def _oauth_token_revoked(self_verifier, token, payload):
            return not verdicts[token]

        return _oauth_token_revoked

    def test_client_revocation_propagates_to_resource_side(self):
        """Invariant 2b: a PLAT-47 client revocation propagates to the
        resource side — the pre-revocation access token is inactive at the
        revocation-status endpoint and rejected by the real verifier, the
        pre-revocation refresh token is rejected at the token endpoint, and
        tokens minted AFTER the revocation stay active."""
        # iat has 1-second granularity: backdate the pre-revocation mint
        # (iat = T-5s) and the revocation clock (cutoff = T-2s) so the
        # post-revocation mint's real-clock iat is strictly after the cutoff
        # without being future-dated (which would fail signature validation).
        from rest_framework_simplejwt.tokens import aware_utcnow
        from django.utils import timezone as dj_tz
        real_now = dj_tz.now()
        with mock.patch(
            "rest_framework_simplejwt.tokens.aware_utcnow",
            return_value=real_now - timedelta(seconds=5),
        ):
            pre = self._mint(family="fam-cutoff")
        old_access, old_refresh = pre["access_token"], pre["refresh_token"]

        # Control before revocation: active at the status endpoint.
        self.assertTrue(self._revocation_status(old_access).data["active"])

        with mock.patch(
            "django.utils.timezone.now",
            return_value=real_now - timedelta(seconds=2),
        ):
            resp = self._revoke_client()
        self.assertEqual(resp.status_code, 200)

        # Resource side: pre-revocation access token is inactive...
        old_active = self._revocation_status(old_access).data["active"]
        self.assertFalse(old_active)
        # ...and the real verifier rejects it on that verdict, while a
        # post-revocation mint (real-clock iat, strictly after the cutoff)
        # stays active at the endpoint and authenticates.
        post = _mint_tokens(
            self.user, self.client_obj, SCOPE, ISSUER,
            user_agent="test", token_family="fam-post",
        )
        post_active = self._revocation_status(post["access_token"]).data["active"]
        self.assertTrue(post_active)

        verifier = self._verifier()
        verdicts = {old_access: old_active, post["access_token"]: post_active}
        with mock.patch.object(
            mcp_base.ShizuhaTokenVerifier, "_oauth_token_revoked",
            new=self._verdict_bridge(verdicts),
        ):
            self.assertIsNone(self._verify(verifier, old_access))
            self.assertIsNotNone(self._verify(verifier, post["access_token"]))

        # ID boundary: the pre-revocation refresh token no longer refreshes.
        resp = self._refresh(old_refresh)
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.data["error"], "invalid_grant")


class RotationInvariantTests(CredentialLifecycleTestMixin):
    def _assert_grants_preserved(self, tokens, family):
        access_payload = _rs256_decode(tokens["access_token"])
        refresh_payload = _rs256_decode(tokens["refresh_token"])
        self.assertEqual(access_payload["scope"], SCOPE)
        self.assertEqual(refresh_payload["scope"], SCOPE)
        self.assertEqual(access_payload["client_id"], self.client_obj.client_id)
        self.assertEqual(refresh_payload["client_id"], self.client_obj.client_id)
        self.assertEqual(access_payload["user_id"], self.user.pk)
        self.assertEqual(refresh_payload["user_id"], self.user.pk)
        self.assertEqual(refresh_payload["token_family"], family)

    def test_rotation_invalidates_old_and_preserves_grants(self):
        """Invariant 3a: rotating consumes the old refresh token (ledger +
        RevokedToken 'refresh rotation') while scope/client/subject/family
        grants carry into the descendant."""
        tokens = self._mint(family="fam-rot")
        r1 = tokens["refresh_token"]
        r1_jti = _rs256_decode(r1)["jti"]

        resp = self._refresh(r1)
        self.assertEqual(resp.status_code, 200)
        r2 = resp.data["refresh_token"]
        self.assertNotEqual(r2, r1)
        self._assert_grants_preserved(resp.data, "fam-rot")

        # Old token invalidated: ledger row revoked + RevokedToken recorded.
        self.assertTrue(
            IssuedRefreshToken.objects.filter(
                jti=r1_jti, revoked_at__isnull=False,
            ).exists()
        )
        self.assertTrue(
            RevokedToken.objects.filter(
                jti=r1_jti, reason="refresh rotation",
            ).exists()
        )
        resp = self._refresh(r1)
        self.assertEqual(resp.status_code, 400)

    def test_rotation_chain_preserves_grants_across_generations(self):
        """Invariant 3b: grants survive a multi-generation rotation chain and
        every consumed generation is rejected — with replay-triggered
        fail-closed family revocation leaving no active descendant."""
        family = "fam-chain"
        tokens = self._mint(family=family)
        consumed = []
        for generation in range(3):
            resp = self._refresh(tokens["refresh_token"])
            self.assertEqual(resp.status_code, 200, f"generation {generation}")
            self._assert_grants_preserved(resp.data, family)
            consumed.append(tokens["refresh_token"])
            tokens = resp.data

        # Every consumed generation is rejected — and because each rejection
        # is a replay, DRV-106 fail-closed revokes the whole family, so no
        # active descendant (including the latest) survives.
        for old in consumed:
            self.assertEqual(self._refresh(old).status_code, 400)
        self.assertFalse(
            IssuedRefreshToken.objects.filter(
                user=self.user, client=self.client_obj,
                token_family=family, revoked_at__isnull=True,
            ).exists(),
            "replaying a consumed generation must revoke the whole family",
        )
