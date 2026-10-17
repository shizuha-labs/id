from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from identity.views import _fetch_project_memberships, _populate_standard_claims


class _Token(dict):
    pass


class ProjectMembershipClaimTests(SimpleTestCase):
    @mock.patch('identity.views._admin_req.get')
    def test_fetch_project_memberships_reads_admin_projection(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            'project_memberships': {'36': 'member'},
            'project_ids': [36],
        }
        user = SimpleNamespace(id=7, email='dev@shizuha.com')

        ids, roles = _fetch_project_memberships(user)

        self.assertEqual(ids, [36])
        self.assertEqual(roles, {'36': 'member'})
        mock_get.assert_called_once()
        self.assertEqual(
            mock_get.call_args.args[0],
            'http://shizuha-admin:8003/api/internal/users/7/project-memberships/',
        )
        self.assertEqual(mock_get.call_args.kwargs['params'], {'email': 'dev@shizuha.com'})

    @mock.patch('identity.views._fetch_project_memberships', return_value=([36], {'36': 'member'}))
    @mock.patch('identity.views._fetch_org_memberships', return_value={'1': 'member'})
    def test_standard_claims_include_project_membership_projection(self, _orgs, _projects):
        token = _Token()
        user = SimpleNamespace(
            id=7,
            email='dev@shizuha.com',
            username='dev',
            first_name='',
            last_name='',
            is_staff=False,
            is_superuser=False,
            profile=SimpleNamespace(account_type='human'),
        )

        _populate_standard_claims(token, user)

        self.assertEqual(token['project_ids'], [36])
        self.assertEqual(token['project_roles'], {'36': 'member'})
        self.assertEqual(token['organization_memberships'], {'1': 'member'})

    @mock.patch(
        'identity.oauth_views._fetch_membership_projection',
        return_value=({'1': 'member'}, [36], {'36': 'member'}),
    )
    def test_oidc_claims_include_project_membership_projection(self, _projection):
        from identity.oauth_views import _oidc_claims_for_user
        user = SimpleNamespace(
            pk=7,
            id=7,
            email='dev@shizuha.com',
            username='dev',
            first_name='',
            last_name='',
            profile=SimpleNamespace(account_type='human'),
        )

        claims = _oidc_claims_for_user(user)

        self.assertEqual(claims['project_ids'], [36])
        self.assertEqual(claims['project_roles'], {'36': 'member'})
