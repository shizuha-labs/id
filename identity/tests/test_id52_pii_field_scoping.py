"""
Regression tests for ID-52 (PII field-scoping) as revised 2026-07-06 after the
platform-wide Pulse-assignment outage.

Contract now:
- /api/internal/ endpoints are service-to-service ONLY. Any request that
  arrived through the public ingress (detected by X-Forwarded-For/X-Real-IP,
  which nginx always appends and in-cluster Service calls lack) is 404'd by
  InternalApiIngressGuardMiddleware — full stop. This closes the actual hole
  ID-52 was defending against (the internal API was publicly mounted via the
  `shizuha-id-backend` ingress).
- Direct in-cluster calls (no forwarding headers) receive the FULL
  UserSerializer, unauthenticated included: Pulse/Connect/Hive key identity
  by EMAIL and platform assignment broke when ID-52 stripped it.
- _scoped_user_serializer keeps the staff/self/public split as defense in
  depth for any ingress-borne request that ever bypasses the middleware.
"""
from types import SimpleNamespace

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import AccessToken

from identity.internal_urls import _scoped_user_serializer
from identity.serializers import PublicUserSerializer, UserSerializer

User = get_user_model()

# Fields that must NEVER appear for an untrusted cross-user lookup
_PRIVATE_FIELDS = {
    'email', 'first_name', 'last_name', 'is_staff', 'is_superuser',
    'is_active', 'date_joined', 'approval_status', 'lifecycle_state', 'profile',
}

# Fields that must always appear for any successful lookup (public minimum)
_PUBLIC_FIELDS = {'id', 'username', 'display_name', 'account_type'}

# Simulates a request proxied by the public ingress.
_INGRESS_HEADERS = {'HTTP_X_FORWARDED_FOR': '203.0.113.7'}


def _jwt_for(user):
    return str(AccessToken.for_user(user))


class InternalUserReadTestBase(TestCase):
    """Shared fixtures for by-id / by-email / by-username reads."""

    def setUp(self):
        self.alice = User.objects.create_user(
            username='alice52', email='alice52@example.com', password='pass',
            first_name='Alice', last_name='Smith',
        )
        self.bob = User.objects.create_user(
            username='bob52', email='bob52@example.com', password='pass',
        )
        self.staff_user = User.objects.create_user(
            username='staff52', email='staff52@example.com', password='pass',
            is_staff=True,
        )

    def _client(self, auth_user=None, via_ingress=False):
        client = APIClient()
        if auth_user:
            client.credentials(HTTP_AUTHORIZATION=f'Bearer {_jwt_for(auth_user)}')
        self._extra = _INGRESS_HEADERS if via_ingress else {}
        return client


class InternalReadByIdTest(InternalUserReadTestBase):
    def _get(self, user_id, auth_user=None, via_ingress=False):
        client = self._client(auth_user, via_ingress)
        return client.get(f'/api/internal/users/{user_id}/', **self._extra)

    def test_in_cluster_unauthenticated_returns_full_fields(self):
        # THE 2026-07-06 regression: Pulse's user_service is an unauthenticated
        # in-cluster consumer and MUST receive email or /assign/ 500s fleet-wide.
        res = self._get(self.alice.id)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data.get('email'), 'alice52@example.com')
        self.assertIn('profile', data)
        self.assertTrue(_PUBLIC_FIELDS.issubset(data.keys()))

    def test_ingress_borne_request_is_404(self):
        res = self._get(self.alice.id, via_ingress=True)
        self.assertEqual(res.status_code, 404)

    def test_ingress_borne_request_is_404_even_authenticated(self):
        res = self._get(self.alice.id, auth_user=self.staff_user, via_ingress=True)
        self.assertEqual(res.status_code, 404)

    def test_staff_read_returns_full_fields(self):
        res = self._get(self.alice.id, auth_user=self.staff_user)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn('email', data)
        self.assertIn('profile', data)


class InternalReadByUsernameTest(InternalUserReadTestBase):
    def _get(self, username, auth_user=None, via_ingress=False):
        client = self._client(auth_user, via_ingress)
        return client.get('/api/internal/users/by-username/',
                          {'username': username}, **self._extra)

    def test_in_cluster_returns_full_fields(self):
        res = self._get('alice52')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json().get('email'), 'alice52@example.com')

    def test_ingress_borne_request_is_404(self):
        res = self._get('alice52', via_ingress=True)
        self.assertEqual(res.status_code, 404)


class InternalReadByEmailTest(InternalUserReadTestBase):
    def _get(self, email, auth_user=None, via_ingress=False):
        client = self._client(auth_user, via_ingress)
        return client.get('/api/internal/users/by-email/',
                          {'email': email}, **self._extra)

    def test_in_cluster_returns_full_fields(self):
        res = self._get('alice52@example.com')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json().get('email'), 'alice52@example.com')

    def test_ingress_borne_request_is_404(self):
        res = self._get('alice52@example.com', via_ingress=True)
        self.assertEqual(res.status_code, 404)


class InternalUserListTest(InternalUserReadTestBase):
    def _get(self, ids=None, auth_user=None, via_ingress=False):
        client = self._client(auth_user, via_ingress)
        params = {}
        if ids:
            params['ids'] = ','.join(str(i) for i in ids)
        return client.get('/api/internal/users/', params, **self._extra)

    def test_unauthenticated_list_returns_401(self):
        # The list view still explicitly requires auth — anonymous directory
        # enumeration stays prohibited even for in-cluster callers.
        res = self._get(ids=[self.alice.id, self.bob.id])
        self.assertEqual(res.status_code, 401)

    def test_in_cluster_authenticated_list_returns_full(self):
        res = self._get(ids=[self.alice.id, self.bob.id], auth_user=self.alice)
        self.assertEqual(res.status_code, 200)
        for item in res.json()['results']:
            self.assertIn('email', item)

    def test_ingress_borne_list_is_404(self):
        res = self._get(ids=[self.alice.id], auth_user=self.staff_user, via_ingress=True)
        self.assertEqual(res.status_code, 404)


class ScopedSerializerDefenseInDepthTest(TestCase):
    """The staff/self/public split must survive for ingress-borne requests
    (defense in depth should the middleware ever be removed)."""

    def setUp(self):
        self.alice = User.objects.create_user(
            username='alice52d', email='alice52d@example.com', password='pass',
        )
        self.staff_user = User.objects.create_user(
            username='staff52d', email='staff52d@example.com', password='pass',
            is_staff=True,
        )

    def _request(self, user, via_ingress=True):
        meta = dict(_INGRESS_HEADERS) if via_ingress else {}
        return SimpleNamespace(user=user, META=meta)

    def test_ingress_anonymous_gets_public(self):
        anon = SimpleNamespace(is_authenticated=False)
        cls = _scoped_user_serializer(self._request(anon), target_user=self.alice)
        self.assertIs(cls, PublicUserSerializer)

    def test_ingress_cross_user_gets_public(self):
        cls = _scoped_user_serializer(self._request(self.alice),
                                      target_user=self.staff_user)
        self.assertIs(cls, PublicUserSerializer)

    def test_ingress_staff_gets_full(self):
        cls = _scoped_user_serializer(self._request(self.staff_user),
                                      target_user=self.alice)
        self.assertIs(cls, UserSerializer)

    def test_ingress_self_read_gets_full(self):
        cls = _scoped_user_serializer(self._request(self.alice),
                                      target_user=self.alice)
        self.assertIs(cls, UserSerializer)

    def test_in_cluster_gets_full(self):
        anon = SimpleNamespace(is_authenticated=False)
        cls = _scoped_user_serializer(self._request(anon, via_ingress=False),
                                      target_user=self.alice)
        self.assertIs(cls, UserSerializer)


class PublicUserSerializerDisplayNameTest(TestCase):
    """ID-57: PublicUserSerializer.display_name must be username, never real name.

    PublicUserSerializer is the defense-in-depth serializer for ingress-borne
    requests that bypass InternalApiIngressGuardMiddleware. Per the ID-51
    PII-scope matrix, first_name/last_name are NOT public-directory-safe;
    display_name must always be the username in this serializer.
    """

    def setUp(self):
        self.alice = User.objects.create_user(
            username='alice57', email='alice57@example.com', password='pass',
            first_name='Alice', last_name='Smith',
        )

    def test_display_name_is_username_not_real_name(self):
        data = PublicUserSerializer(self.alice).data
        self.assertEqual(data['display_name'], 'alice57',
                         "PublicUserSerializer.display_name must be username (ID-51 matrix)")
        self.assertNotEqual(data['display_name'], 'Alice Smith',
                            "PublicUserSerializer must not expose first_name+last_name")

    def test_display_name_equals_username_field(self):
        data = PublicUserSerializer(self.alice).data
        self.assertEqual(data['display_name'], data['username'])

    def test_display_name_when_no_real_name_set(self):
        user = User.objects.create_user(
            username='noname57', email='noname57@example.com', password='pass',
        )
        data = PublicUserSerializer(user).data
        self.assertEqual(data['display_name'], 'noname57')
