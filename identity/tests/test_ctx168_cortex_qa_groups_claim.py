"""CTX-168: `groups` claim in the standard claim set.

_populate_standard_claims emits the user's Django group names as a flat
`groups` claim — but ONLY when the user belongs to ≥1 group, so existing
tokens are unchanged. Cortex's IsQAReadOnly (CTX-218) reads this claim to
grant read-only access to /v1/admin/nodes and /v1/admin/backends for members
of the `cortex-qa` group.
"""
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase

from identity.views import _populate_standard_claims

User = get_user_model()
_projection_patcher = None


def setUpModule():
    global _projection_patcher
    _projection_patcher = mock.patch(
        'identity.views._fetch_membership_projection',
        return_value=({}, [], {}),
    )
    _projection_patcher.start()


def tearDownModule():
    _projection_patcher.stop()


class _Token(dict):
    pass


class _Groups:
    """Minimal stand-in for user.groups supporting values_list('name', flat=True)."""

    def __init__(self, names):
        self._names = list(names)

    def values_list(self, field, flat=False):
        assert field == 'name' and flat is True
        return list(self._names)


def _user(groups_names, *, pk=7, account_type='agent'):
    return SimpleNamespace(
        pk=pk,
        id=pk,
        email='kei@shizuha.com',
        username='kei',
        first_name='',
        last_name='',
        is_staff=False,
        is_superuser=False,
        profile=SimpleNamespace(account_type=account_type),
        groups=_Groups(groups_names),
    )


@mock.patch('identity.views._fetch_project_memberships', return_value=([], {}))
@mock.patch('identity.views._fetch_org_memberships', return_value={})
class CortexQAGroupsClaimTests(SimpleTestCase):
    def test_cortex_qa_member_gets_groups_claim(self, _orgs, _projects):
        token = _Token()
        _populate_standard_claims(token, _user(['cortex-qa']))
        self.assertEqual(token['groups'], ['cortex-qa'])

    def test_groups_claim_is_sorted_deterministic(self, _orgs, _projects):
        token = _Token()
        _populate_standard_claims(token, _user(['zeta', 'cortex-qa', 'alpha']))
        self.assertEqual(token['groups'], ['alpha', 'cortex-qa', 'zeta'])

    def test_no_groups_means_no_claim(self, _orgs, _projects):
        """Users in no group get NO `groups` key — existing tokens unchanged."""
        token = _Token()
        _populate_standard_claims(token, _user([]))
        self.assertNotIn('groups', token)

    def test_unsaved_user_no_claim_no_error(self, _orgs, _projects):
        token = _Token()
        _populate_standard_claims(token, _user(['cortex-qa'], pk=None))
        self.assertNotIn('groups', token)

    def test_missing_groups_relation_degrades_silently(self, _orgs, _projects):
        """Federated/synthetic users without a groups relation must not error."""
        token = _Token()
        user = SimpleNamespace(
            pk=7, id=7, email='svc@shizuha.com', username='svc',
            first_name='', last_name='', is_staff=False, is_superuser=False,
            profile=SimpleNamespace(account_type='agent'),
        )  # no .groups attribute
        _populate_standard_claims(token, user)
        self.assertNotIn('groups', token)


@mock.patch('identity.views.get_effective_services', return_value=[])
@mock.patch('identity.views._fetch_project_memberships', return_value=([], {}))
@mock.patch('identity.views._fetch_org_memberships', return_value={})
class ApiTokenGroupsClaimTests(TestCase):
    def test_api_token_access_copy_preserves_groups_claim(self, _orgs, _projects, _services):
        from django.contrib.auth.models import Group
        from rest_framework.test import APIRequestFactory, force_authenticate
        from identity.agent_tokens import PlatformAccessToken

        from identity.models import UserProfile
        from identity.views import ApiTokenView

        user = User.objects.create_user(
            username='kei',
            email='kei@shizuha.com',
            password='pw',
        )
        UserProfile.objects.update_or_create(user=user, defaults={'account_type': 'human'})
        group, _ = Group.objects.get_or_create(name='cortex-qa')
        user.groups.add(group)

        request = APIRequestFactory().post(
            '/api/auth/api-token/',
            {'label': 'qa', 'ttl_days': 30},
            format='json',
        )
        force_authenticate(request, user=user)

        response = ApiTokenView.as_view()(request)

        self.assertEqual(response.status_code, 200)
        access = PlatformAccessToken(response.data['access'])
        self.assertEqual(access['groups'], ['cortex-qa'])
