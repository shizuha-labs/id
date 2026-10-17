"""ID-54: no user-existence oracle on the internal cross-user lookups.

Parent epic ID-6. Acceptance: a lookup for a NONEXISTENT user and a lookup for
an EXISTING-but-unauthorized user must be indistinguishable (same status + body,
no shape/timing oracle), so a caller cannot infer account existence.

Post-ID-52 the `/api/internal/users/{by-id,by-email,by-username}` lookups are
ingress-guarded by `InternalApiIngressGuardMiddleware` (settings.py): any request
that arrived through the public ingress (`X-Forwarded-For`/`X-Real-IP` present) is
404'd BEFORE the view or any DB access runs. Under the accepted network-trust
posture (documented in the ID-51 matrix `49cd66db`), the only "unauthorized"
caller class for these internal endpoints is the EXTERNAL one -- in-cluster
service callers (Connect DM resolution, Pulse assignment) are trusted.

ID-52 already asserts an ingress-borne request gets 404. This ID-54 slice adds
the specific ANTI-ENUMERATION guarantee: an external lookup for an EXISTING user
and for a NONEXISTENT user are BYTE-IDENTICAL. Because the guard short-circuits
before the view/DB, the identical 404 is the guard's body (not the view's
`User not found`), which also means there is no response-shape or DB-timing side
channel. In-cluster (non-forwarded) callers keep truthful 200/404, so
service-to-service resolution is unaffected (CON-133-class regression guard).
"""
from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

User = get_user_model()

_INGRESS = {'HTTP_X_FORWARDED_FOR': '203.0.113.7'}   # simulates the public ingress
_GUARD_404_BODY = {'error': 'Not found'}             # InternalApiIngressGuardMiddleware
_VIEW_404_BODY = {'error': 'User not found'}         # the lookup view's own 404


class NoExternalExistenceOracleTest(TestCase):
    """External (ingress-borne) EXISTING vs NONEXISTENT lookups are identical."""

    def setUp(self):
        self.user = User.objects.create_user(
            username='real54', email='real54@example.com', password='pass')

    def _ingress_get(self, path, params=None):
        return APIClient().get(path, params or {}, **_INGRESS)

    def _assert_indistinguishable(self, r_exist, r_missing):
        # existing-user request would be 200 without the guard; the guard makes
        # it a 404 with the GUARD's body (not the view's) -> proves the guard
        # short-circuited before the view/DB, so no existence/shape/timing oracle.
        self.assertEqual(r_exist.status_code, 404)
        self.assertEqual(r_missing.status_code, 404)
        self.assertEqual(r_exist.json(), _GUARD_404_BODY)
        self.assertEqual(r_missing.json(), _GUARD_404_BODY)
        self.assertEqual(r_exist.content, r_missing.content)              # byte-identical
        self.assertEqual(r_exist['Content-Type'], r_missing['Content-Type'])

    def test_by_username_no_oracle(self):
        self._assert_indistinguishable(
            self._ingress_get('/api/internal/users/by-username/', {'username': 'real54'}),
            self._ingress_get('/api/internal/users/by-username/', {'username': 'ghost_nobody'}))

    def test_by_email_no_oracle(self):
        self._assert_indistinguishable(
            self._ingress_get('/api/internal/users/by-email/', {'email': 'real54@example.com'}),
            self._ingress_get('/api/internal/users/by-email/', {'email': 'ghost@nobody.io'}))

    def test_by_id_no_oracle(self):
        self._assert_indistinguishable(
            self._ingress_get(f'/api/internal/users/{self.user.pk}/'),
            self._ingress_get('/api/internal/users/999999/'))


class InClusterTrustUnaffectedTest(TestCase):
    """Non-forwarded (in-cluster) callers keep truthful 200/404 -> network-trust
    posture intact; Connect DM username->user resolution unaffected."""

    def setUp(self):
        self.user = User.objects.create_user(
            username='svc54', email='svc54@example.com', password='pass')

    def test_in_cluster_existing_resolves_200(self):
        res = APIClient().get('/api/internal/users/by-username/', {'username': 'svc54'})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json().get('email'), 'svc54@example.com')

    def test_in_cluster_nonexistent_is_view_404(self):
        res = APIClient().get('/api/internal/users/by-username/', {'username': 'ghost_nobody'})
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json(), _VIEW_404_BODY)   # the view's 404 -> guard did NOT fire
