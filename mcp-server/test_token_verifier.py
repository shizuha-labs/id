import asyncio
import json
import os
import sys
import time
import unittest
from unittest import mock

import jwt

sys.path.insert(0, os.path.dirname(__file__))
from base import (  # noqa: E402
    ShizuhaTokenVerifier,
    _oauth_issuer,
    _register_oauth_discovery_routes,
    _resource_server_url,
)


class _FakeSigningKey:
    key = "rs-key"


class _FakeJwksClient:
    urls = []

    def __init__(self, url):
        self.url = url
        self.urls.append(url)

    def get_signing_key_from_jwt(self, token):
        return _FakeSigningKey()


class OAuthUrlDefaultsTests(unittest.TestCase):
    @mock.patch.dict(os.environ, {}, clear=True)
    def test_defaults_use_canonical_https_without_redirects(self):
        self.assertEqual(_oauth_issuer(), "https://shizuha.com/id")
        self.assertEqual(
            _resource_server_url("id"),
            "https://shizuha.com/mcp/id",
        )

    @mock.patch.dict(os.environ, {}, clear=True)
    def test_discovery_advertises_canonical_authorization_and_resource(self):
        routes = {}

        class FakeMcp:
            def custom_route(self, path, methods):
                def register(handler):
                    routes[path] = handler
                    return handler

                return register

        from starlette.requests import Request

        _register_oauth_discovery_routes(FakeMcp(), "id")
        request = Request(
            {
                "type": "http",
                "method": "GET",
                "scheme": "https",
                "path": "/.well-known/oauth-protected-resource",
                "raw_path": b"/.well-known/oauth-protected-resource",
                "query_string": b"",
                "headers": [
                    (b"host", b"shizuha.com"),
                    (b"x-forwarded-prefix", b"/mcp/id"),
                ],
                "server": ("shizuha.com", 443),
            }
        )
        response = asyncio.run(
            routes["/.well-known/oauth-protected-resource"](request)
        )
        metadata = json.loads(response.body)
        self.assertEqual(metadata["resource"], "https://shizuha.com/mcp/id")
        self.assertEqual(
            metadata["authorization_servers"],
            ["https://shizuha.com/id"],
        )


class ShizuhaTokenVerifierTests(unittest.TestCase):
    def setUp(self):
        _FakeJwksClient.urls.clear()

    def test_hs256_shared_secret_token_is_rejected(self):
        token = jwt.encode(
            {"user_id": 7, "exp": int(time.time()) + 3600},
            "secret",
            algorithm="HS256",
        )
        verifier = ShizuhaTokenVerifier("test", "https://id.example")

        result = asyncio.run(verifier.verify_token(token))

        self.assertIsNone(result)

    @mock.patch.dict(os.environ, {}, clear=True)
    def test_rs256_jwks_token_authenticates(self):
        token = "header.payload.signature"
        verifier = ShizuhaTokenVerifier("test", _oauth_issuer())
        with mock.patch("jwt.PyJWKClient", _FakeJwksClient), mock.patch(
            "base.jwt.decode",
            return_value={"user_id": 7, "exp": int(time.time()) + 3600},
        ) as decode:
            result = asyncio.run(verifier.verify_token(token))

        self.assertIsNotNone(result)
        self.assertEqual(result.client_id, "7")
        decode.assert_called_once()
        self.assertEqual(decode.call_args.kwargs["algorithms"], ["RS256"])
        self.assertEqual(
            _FakeJwksClient.urls,
            ["https://shizuha.com/id/.well-known/jwks.json"],
        )

    def test_expired_rs256_token_is_rejected_for_refresh(self):
        token = "header.payload.signature"
        verifier = ShizuhaTokenVerifier("test", "https://id.example")
        with mock.patch("jwt.PyJWKClient", _FakeJwksClient), mock.patch(
            "base.jwt.decode",
            side_effect=jwt.ExpiredSignatureError("expired"),
        ):
            result = asyncio.run(verifier.verify_token(token))

        self.assertIsNone(result)

    # PLAT-11138: dual-layer reject probe — the verifier must distinguish
    # bearer expiry (client churn) from JWKS-lane staleness (server-side
    # silent-401 cascade class) instead of collapsing both into None.

    def test_expired_reject_classifies_as_expired_layer(self):
        token = "header.payload.signature"
        verifier = ShizuhaTokenVerifier("test", "https://id.example")
        with mock.patch("jwt.PyJWKClient", _FakeJwksClient), mock.patch(
            "base.jwt.decode",
            side_effect=jwt.ExpiredSignatureError("expired"),
        ):
            asyncio.run(verifier.verify_token(token))

        snap = verifier.reject_reason_snapshot()
        self.assertEqual(snap["last_reject_reason"], "expired")
        self.assertEqual(snap["counters"]["expired"], 1)
        self.assertEqual(snap["counters"]["jwks_unavailable"], 0)

    def test_jwks_failure_classifies_as_key_layer_and_fails_loud(self):
        import logging

        from jwt.exceptions import PyJWKClientConnectionError

        token = "header.payload.signature"
        verifier = ShizuhaTokenVerifier("test", "https://id.example")
        with self.assertLogs(verifier._logger, level=logging.WARNING) as logs:
            with mock.patch("jwt.PyJWKClient", _FakeJwksClient), mock.patch(
                "base.jwt.decode",
                side_effect=PyJWKClientConnectionError("jwks fetch failed"),
            ):
                result = asyncio.run(verifier.verify_token(token))

        self.assertIsNone(result)
        snap = verifier.reject_reason_snapshot()
        self.assertEqual(snap["last_reject_reason"], "jwks_unavailable")
        self.assertEqual(snap["counters"]["jwks_unavailable"], 1)
        self.assertIn("JWKS lane unavailable", "\n".join(logs.output))

    def test_no_matching_key_is_token_shaped_not_key_lane(self):
        # PLAT-11138 discriminator: PyJWKClientError("no matching key") is the
        # TOKEN naming a key the JWKS does not carry (HS256 presented to an
        # RS256-only verifier) — that is `invalid`, not a key-lane outage.
        from jwt.exceptions import PyJWKClientError

        token = "header.payload.signature"
        verifier = ShizuhaTokenVerifier("test", "https://id.example")
        with mock.patch("jwt.PyJWKClient", _FakeJwksClient), mock.patch(
            "base.jwt.decode",
            side_effect=PyJWKClientError("no matching key"),
        ):
            asyncio.run(verifier.verify_token(token))

        snap = verifier.reject_reason_snapshot()
        self.assertEqual(snap["last_reject_reason"], "invalid")
        self.assertEqual(snap["counters"]["invalid"], 1)
        self.assertEqual(snap["counters"]["jwks_unavailable"], 0)

    def test_invalid_reject_classifies_as_invalid_layer(self):
        token = "header.payload.signature"
        verifier = ShizuhaTokenVerifier("test", "https://id.example")
        with mock.patch("jwt.PyJWKClient", _FakeJwksClient), mock.patch(
            "base.jwt.decode",
            side_effect=jwt.InvalidTokenError("bad signature"),
        ):
            asyncio.run(verifier.verify_token(token))

        snap = verifier.reject_reason_snapshot()
        self.assertEqual(snap["last_reject_reason"], "invalid")
        self.assertEqual(snap["counters"]["invalid"], 1)


if __name__ == "__main__":
    unittest.main()
