"""
Regression tests for ID-58 Phase A: accept-and-log internal-service-token
on /api/internal/users/* lookups.

Phase A contract:
- Token-bearing callers (valid X-Internal-Service-Token) → UserSerializer (full, incl. email).
- Non-token in-cluster callers → UserSerializer via network-trust (no behavior change).
- Ingress-borne requests → 404 from InternalApiIngressGuardMiddleware (unchanged).
- _check_service_token: returns True iff token configured AND header matches.
"""
from unittest.mock import MagicMock, patch
from django.test import TestCase, override_settings

from identity.internal_urls import _check_service_token, _scoped_user_serializer
from identity.serializers import PublicUserSerializer, UserSerializer


_VALID_TOKEN = 'test-internal-service-token-abc123'
_WRONG_TOKEN = 'wrong-token'


def _make_request(token=None, via_ingress=False, user=None):
    """Build a minimal request stub for _check_service_token / _scoped_user_serializer."""
    req = MagicMock()
    req.headers = {}
    if token is not None:
        req.headers['X-Internal-Service-Token'] = token
    req.META = {
        'HTTP_USER_AGENT': 'test-agent/1.0',
    }
    if user is None:
        anon = MagicMock()
        anon.is_authenticated = False
        req.user = anon
    else:
        req.user = user
    req._via_ingress = via_ingress
    return req


class CheckServiceTokenTests(TestCase):
    """Unit tests for _check_service_token — no DB, no Django setup needed."""

    @override_settings(INTERNAL_SERVICE_TOKEN=_VALID_TOKEN)
    def test_valid_token_returns_true(self):
        req = _make_request(token=_VALID_TOKEN)
        self.assertTrue(_check_service_token(req))

    @override_settings(INTERNAL_SERVICE_TOKEN=_VALID_TOKEN)
    def test_wrong_token_returns_false(self):
        req = _make_request(token=_WRONG_TOKEN)
        self.assertFalse(_check_service_token(req))

    @override_settings(INTERNAL_SERVICE_TOKEN=_VALID_TOKEN)
    def test_missing_token_returns_false(self):
        req = _make_request(token=None)
        self.assertFalse(_check_service_token(req))

    @override_settings(INTERNAL_SERVICE_TOKEN='')
    def test_unconfigured_token_returns_false(self):
        # Phase A no-op: if INTERNAL_SERVICE_TOKEN is empty, always False.
        req = _make_request(token=_VALID_TOKEN)
        self.assertFalse(_check_service_token(req))

    @override_settings(INTERNAL_SERVICE_TOKEN=_VALID_TOKEN)
    def test_empty_header_value_returns_false(self):
        req = _make_request(token='')
        self.assertFalse(_check_service_token(req))


class ScopedSerializerTokenTests(TestCase):
    """Unit tests for _scoped_user_serializer token-path (Phase A, ID-58).

    Patches request_via_ingress so tests are independent of the middleware.
    """

    @override_settings(INTERNAL_SERVICE_TOKEN=_VALID_TOKEN)
    def test_token_bearer_gets_full_serializer(self):
        """Token-authenticated caller always gets UserSerializer (even if via_ingress)."""
        req = _make_request(token=_VALID_TOKEN, via_ingress=True)
        with patch('identity.internal_api_guard.request_via_ingress', return_value=True):
            cls = _scoped_user_serializer(req)
        self.assertIs(cls, UserSerializer)

    @override_settings(INTERNAL_SERVICE_TOKEN=_VALID_TOKEN)
    def test_in_cluster_no_token_still_gets_full_serializer(self):
        """Non-token in-cluster caller: network-trust path unchanged (Phase A)."""
        req = _make_request(token=None, via_ingress=False)
        with patch('identity.internal_api_guard.request_via_ingress', return_value=False):
            cls = _scoped_user_serializer(req)
        self.assertIs(cls, UserSerializer)

    @override_settings(INTERNAL_SERVICE_TOKEN=_VALID_TOKEN)
    def test_ingress_no_token_anonymous_gets_public_serializer(self):
        """Ingress-borne anonymous non-token caller → PublicUserSerializer (defense in depth)."""
        req = _make_request(token=None, via_ingress=True)
        with patch('identity.internal_api_guard.request_via_ingress', return_value=True):
            cls = _scoped_user_serializer(req)
        self.assertIs(cls, PublicUserSerializer)

    @override_settings(INTERNAL_SERVICE_TOKEN=_VALID_TOKEN)
    def test_wrong_token_ingress_anonymous_gets_public_serializer(self):
        """Wrong token + ingress-borne + anonymous → PublicUserSerializer (no privilege escalation)."""
        req = _make_request(token=_WRONG_TOKEN, via_ingress=True)
        with patch('identity.internal_api_guard.request_via_ingress', return_value=True):
            cls = _scoped_user_serializer(req)
        self.assertIs(cls, PublicUserSerializer)
