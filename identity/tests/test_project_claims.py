"""
Tests for SCS-31: project_ids / project_roles JWT claims.

Validates:
  - _fetch_project_memberships returns correct (ids, roles) on admin 200
  - graceful degradation: admin 500 → empty lists, no exception propagated
  - graceful degradation: RequestException → empty lists, no exception propagated
  - claims are stamped atomically onto the token by _populate_standard_claims
"""
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.test import TestCase

from identity.views import _fetch_project_memberships, _populate_standard_claims


def _make_user(user_id=99, email='tester@shizuha.com'):
    user = MagicMock()
    user.id = user_id
    user.email = email
    user.username = 'tester'
    user.first_name = 'Test'
    user.last_name = 'User'
    user.is_staff = False
    user.is_superuser = False
    profile = SimpleNamespace(account_type='human')
    user.profile = profile
    return user


class FetchProjectMembershipsTest(TestCase):

    def _mock_response(self, status_code, body):
        resp = MagicMock()
        resp.status_code = status_code
        resp.json.return_value = body
        return resp

    @patch('identity.views._admin_req')
    def test_happy_path_returns_ids_and_roles(self, mock_req):
        mock_req.get.return_value = self._mock_response(200, {
            'project_ids': [1, 2, 3],
            'project_memberships': {'1': 'admin', '2': 'member', '3': 'viewer'},
        })
        mock_req.RequestException = Exception

        user = _make_user()
        ids, roles = _fetch_project_memberships(user)

        self.assertEqual(ids, [1, 2, 3])
        self.assertEqual(roles, {'1': 'admin', '2': 'member', '3': 'viewer'})
        mock_req.get.assert_called_once()
        call_kwargs = mock_req.get.call_args
        self.assertEqual(call_kwargs.kwargs.get('timeout', call_kwargs[1].get('timeout')), 1.0)

    @patch('identity.views._admin_req')
    def test_admin_500_returns_empty(self, mock_req):
        mock_req.get.return_value = self._mock_response(500, {})
        mock_req.RequestException = Exception

        ids, roles = _fetch_project_memberships(_make_user())

        self.assertEqual(ids, [])
        self.assertEqual(roles, {})

    @patch('identity.views._admin_req')
    def test_request_exception_degrades_gracefully(self, mock_req):
        import requests
        mock_req.RequestException = requests.RequestException
        mock_req.get.side_effect = requests.RequestException('connection refused')

        ids, roles = _fetch_project_memberships(_make_user())

        self.assertEqual(ids, [])
        self.assertEqual(roles, {})

    @patch('identity.views._admin_req')
    def test_missing_keys_degrade_to_empty(self, mock_req):
        # Admin returns 200 but without project_ids/project_memberships keys
        mock_req.get.return_value = self._mock_response(200, {'other_key': 'value'})
        mock_req.RequestException = Exception

        ids, roles = _fetch_project_memberships(_make_user())

        self.assertEqual(ids, [])
        self.assertEqual(roles, {})


class PopulateStandardClaimsProjectTest(TestCase):
    """Integration: _populate_standard_claims stamps project_ids / project_roles."""

    @patch('identity.views._fetch_project_memberships')
    @patch('identity.views._fetch_org_memberships')
    def test_claims_stamped_on_token(self, mock_org, mock_proj):
        mock_org.return_value = {'1': 'admin'}
        mock_proj.return_value = ([10, 20], {'10': 'admin', '20': 'member'})

        token = {}
        user = _make_user()
        _populate_standard_claims(token, user)

        self.assertEqual(token['project_ids'], [10, 20])
        self.assertEqual(token['project_roles'], {'10': 'admin', '20': 'member'})

    @patch('identity.views._fetch_project_memberships')
    @patch('identity.views._fetch_org_memberships')
    def test_authoritative_empty_projection_is_stamped(self, mock_org, mock_proj):
        mock_org.return_value = {}
        mock_proj.return_value = ([], {})

        token = {}
        _populate_standard_claims(token, _make_user())

        self.assertEqual(token['project_ids'], [])
        self.assertEqual(token['project_roles'], {})
