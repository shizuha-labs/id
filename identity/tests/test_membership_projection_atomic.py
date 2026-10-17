from unittest.mock import MagicMock, patch

import requests
from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIRequestFactory

from identity.storm_views import StormAwareTokenRefreshView
from identity.views import (
    LoginView,
    MembershipProjectionUnavailable,
    _fetch_membership_projection,
    _fetch_org_memberships,
    _fetch_project_memberships,
    get_tokens_for_user,
)


User = get_user_model()
PROJECTION = ({'2': 'owner'}, [36], {'36': 'member'})


class AtomicMembershipProjectionTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = User.objects.create_user(
            username='projection-user',
            email='projection-user@shizuha.com',
            password='correct-password',
        )

    @patch('identity.views._admin_req')
    def test_required_org_projection_rejects_admin_timeout(self, admin):
        admin.RequestException = requests.RequestException
        admin.get.side_effect = requests.Timeout('admin timed out')

        with self.assertRaises(MembershipProjectionUnavailable):
            _fetch_org_memberships(self.user, required=True)

    @patch('identity.views._admin_req')
    def test_required_project_projection_rejects_invalid_success_shape(self, admin):
        response = MagicMock(status_code=200)
        response.json.return_value = {'project_ids': 'not-a-list'}
        admin.get.return_value = response
        admin.RequestException = requests.RequestException

        with self.assertRaises(MembershipProjectionUnavailable):
            _fetch_project_memberships(self.user, required=True)

    @patch(
        'identity.views._fetch_membership_projection',
        side_effect=MembershipProjectionUnavailable(),
    )
    def test_password_login_returns_typed_503_without_tokens(self, _projection):
        request = self.factory.post(
            '/id/api/auth/login/',
            {'username': self.user.username, 'password': 'correct-password'},
            format='json',
        )

        response = LoginView.as_view()(request)

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.data['error'], 'membership_projection_unavailable')
        self.assertNotIn('tokens', response.data)
        self.assertEqual(response['Retry-After'], '1')

    @patch('identity.views.Tool.objects.filter')
    @patch('identity.views._fetch_membership_projection')
    @patch('identity.storm_views.get_strategy')
    def test_failed_refresh_does_not_consume_refresh_token(
        self,
        strategy,
        projection,
        tool_filter,
    ):
        strategy.return_value.record.return_value.should_emit = False
        tool_filter.return_value.values_list.return_value = []
        tool_filter.return_value.filter.return_value.values_list.return_value = []
        projection.return_value = PROJECTION
        tokens = get_tokens_for_user(self.user)

        projection.side_effect = MembershipProjectionUnavailable()
        failed_request = self.factory.post(
            '/id/api/auth/refresh/',
            {'refresh': tokens['refresh']},
            format='json',
        )
        failed = StormAwareTokenRefreshView.as_view()(failed_request)

        self.assertEqual(failed.status_code, 503)
        self.assertEqual(failed.data['error'], 'membership_projection_unavailable')
        self.assertEqual(failed['Retry-After'], '1')

        projection.side_effect = None
        projection.return_value = PROJECTION
        retry_request = self.factory.post(
            '/id/api/auth/refresh/',
            {'refresh': tokens['refresh']},
            format='json',
        )
        retried = StormAwareTokenRefreshView.as_view()(retry_request)

        self.assertEqual(retried.status_code, 200)
        self.assertIn('access', retried.data)


class MembershipProjectionRequiredBindingTests(TestCase):
    """PLAT-5334 / @reika: pin that the MINT path passes ``required=True``.

    The tests above patch ``_fetch_membership_projection`` wholesale, so they
    prove the views handle the exception and prove the fetchers raise when
    called with ``required=True`` by hand — but nothing asserts that the mint
    path actually *binds* the required variant. Flip either call at
    ``views.py:444-445`` to ``required=False`` and every one of them still
    passes, because the fetchers would return ``{}`` / ``[]`` instead of
    raising and no test drives the real function.

    These patch one layer lower (``_admin_req``, the Admin HTTP client) and
    drive the real view, so ``_fetch_membership_projection`` executes with its
    real arguments. If the binding is ever loosened, a token gets minted with
    an authoritative-looking empty projection and these fail.
    """

    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = User.objects.create_user(
            username='binding-user',
            email='binding-user@shizuha.com',
            password='correct-password',
        )

    def _login(self):
        request = self.factory.post(
            '/id/api/auth/login/',
            {'username': self.user.username, 'password': 'correct-password'},
            format='json',
        )
        return LoginView.as_view()(request)

    @patch('identity.views._admin_req.get', side_effect=requests.Timeout('admin down'))
    def test_admin_timeout_during_mint_yields_503_and_no_token(self, _get):
        """The whole point: a real Admin failure must not become a token."""
        response = self._login()

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.data['error'], 'membership_projection_unavailable')
        self.assertNotIn('tokens', response.data)

    @patch('identity.views._admin_req.get')
    def test_admin_non_200_during_mint_yields_503_and_no_token(self, get):
        """Covers the `elif required: raise` branch, untested in either fetcher."""
        get.return_value = MagicMock(status_code=503, json=MagicMock(return_value={}))

        response = self._login()

        self.assertEqual(response.status_code, 503)
        self.assertNotIn('tokens', response.data)

    @patch('identity.views._admin_req.get')
    def test_CONTROL_healthy_admin_still_mints(self, get):
        """Positive control.

        Both assertions above pass against a login endpoint that is simply
        broken. This one fails if the change under test breaks the happy path,
        so 'never mints' cannot masquerade as 'correctly refuses'.
        """
        get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={'memberships': {'2': 'owner'},
                                         'project_memberships': {}, 'project_ids': []}),
        )

        response = self._login()

        self.assertEqual(response.status_code, 200)
        self.assertIn('tokens', response.data)


class MembershipProjectionOutcomeInvariantTests(TestCase):
    """PLAT-5334 #3 condition 3 (@nova's one-bit form).

    `authoritative_empty` is emitted ONLY on a 200 with a well-formed empty
    payload; every non-authoritative path emits a different label AND raises.

    The trap these exist for: `_fetch_org_memberships(required=False)` also
    returns `{}` on failure. If that path recorded `authoritative_empty`, the
    counter would report "this user belongs to nothing" for an Admin outage --
    reproducing, in the metric, exactly the ambiguity the metric exists to
    remove. The label must come from the 200, not from the return value.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username='outcome-user', email='outcome-user@shizuha.com',
            password='pw')

    def _resp(self, status_code, payload):
        return MagicMock(status_code=status_code,
                         json=MagicMock(return_value=payload))

    @patch('identity.views.record_membership_projection_event')
    @patch('identity.views._admin_req.get')
    def test_well_formed_EMPTY_200_is_the_only_authoritative_empty(self, get, rec):
        get.return_value = self._resp(200, {'memberships': {}})
        self.assertEqual(_fetch_org_memberships(self.user, required=True), {})
        rec.assert_called_once_with('authoritative_empty')

    @patch('identity.views.record_membership_projection_event')
    @patch('identity.views._admin_req.get')
    def test_well_formed_POPULATED_200_is_success_not_authoritative_empty(self, get, rec):
        get.return_value = self._resp(200, {'memberships': {'2': 'owner'}})
        _fetch_org_memberships(self.user, required=True)
        rec.assert_called_once_with('success')

    @patch('identity.views.record_membership_projection_event')
    @patch('identity.views._admin_req.get')
    def test_non_200_records_non_200_and_raises(self, get, rec):
        get.return_value = self._resp(503, {})
        with self.assertRaises(MembershipProjectionUnavailable):
            _fetch_org_memberships(self.user, required=True)
        rec.assert_called_once_with('non_200')

    @patch('identity.views.record_membership_projection_event')
    @patch('identity.views._admin_req.get')
    def test_malformed_200_records_invalid_payload_and_raises(self, get, rec):
        get.return_value = self._resp(200, {'memberships': 'not-a-dict'})
        with self.assertRaises(MembershipProjectionUnavailable):
            _fetch_org_memberships(self.user, required=True)
        rec.assert_called_once_with('invalid_payload')

    @patch('identity.views.record_membership_projection_event')
    @patch('identity.views._admin_req.get', side_effect=requests.Timeout('slow'))
    def test_timeout_records_timeout_and_raises(self, get, rec):
        with self.assertRaises(MembershipProjectionUnavailable):
            _fetch_org_memberships(self.user, required=True)
        rec.assert_called_once_with('timeout')

    @patch('identity.views.record_membership_projection_event')
    @patch('identity.views._admin_req.get',
           side_effect=requests.ConnectionError('refused'))
    def test_connection_error_records_request_error_and_raises(self, get, rec):
        with self.assertRaises(MembershipProjectionUnavailable):
            _fetch_org_memberships(self.user, required=True)
        rec.assert_called_once_with('request_error')

    @patch('identity.views.record_membership_projection_event')
    @patch('identity.views._admin_req.get', side_effect=requests.Timeout('slow'))
    def test_THE_INVARIANT_non_required_failure_returns_empty_but_is_NOT_authoritative(
            self, get, rec):
        """The one that matters.

        required=False returns {} on failure — the same value a genuine
        zero-membership user produces. The counter must not conflate them.

        ⚠️ ASSERTION CHANGED with P2-1 (@reika). This previously asserted
        ``'timeout' in recorded``. Gating recordings on ``required`` makes the
        non-required path record NOTHING, so that assertion is now false — and
        the invariant it protects is *stronger* than before rather than weaker:
        the non-mint path cannot mislabel the counter because it cannot reach
        the counter at all. The half that carries the invariant
        (``authoritative_empty`` never from a failure) is kept and is now true
        by construction.
        """
        self.assertEqual(_fetch_org_memberships(self.user, required=False), {})
        recorded = [c.args[0] for c in rec.call_args_list]
        self.assertEqual(
            recorded, [],
            'the non-mint (required=False) path must not feed the mint counter '
            f'— it recorded {recorded}. internal_urls.py:252/259 call this per '
            'candidate inside a directory-listing loop.',
        )
        self.assertNotIn('authoritative_empty', recorded)

    @patch('identity.views.record_membership_projection_event')
    @patch('identity.views._admin_req.get', side_effect=requests.Timeout('slow'))
    def test_CONTROL_the_required_path_still_records_that_same_failure(
            self, get, rec):
        """Positive control for P2-1 — the gate must not be a mute switch.

        Every assertion above is satisfied by a recorder that never fires at
        all, so gating on ``required`` could silently disable the whole metric
        and the suite would stay green. This pins that the *identical* failure
        on the required path still records, so the gate is proven to
        discriminate rather than merely to suppress.
        """
        with self.assertRaises(MembershipProjectionUnavailable):
            _fetch_org_memberships(self.user, required=True)
        rec.assert_called_once_with('timeout')

    @patch('identity.views.record_membership_projection_event')
    @patch('identity.views._admin_req.get')
    def test_project_fetcher_follows_the_same_rule(self, get, rec):
        get.return_value = self._resp(200, {'project_memberships': {},
                                            'project_ids': []})
        _fetch_project_memberships(self.user, required=True)
        rec.assert_called_once_with('authoritative_empty')


class MintLevelProjectionSequenceTests(TestCase):
    """PLAT-5334 #3 / P2-2 — the burst arithmetic's source of truth.

    @nova's live gate needs to know how many `success` and `authoritative_empty`
    records a burst of mints produces. The counter is GLOBAL, so the check is a
    shape assertion rather than an exact-count one — but the per-mint shape has
    to come from somewhere, and the thread's prose form of it was wrong three
    separate times (K+K×1 vs 3K, twice more before that).

    So @reika's requirement, adopted here: **@nova reads her expectations off
    these assertions at the deployed SHA, not off any written formula.** That
    means this class must pin, executably:

      1. the ORDERED per-family sequence for a 0-project identity,
      2. the ORDERED per-family sequence for a populated identity,
      3. that a mint records EXACTLY two events, one per family — the property
         nova's arithmetic divides by, and the one that silently invalidates it
         if a third fetcher is ever added or one is dropped,
      4. the burst totals themselves, computed rather than narrated, so nobody
         transcribes an integer again.

    Order matters and is asserted: `_fetch_membership_projection` reads the org
    family first (`views.py:493`) then the project family (`:494`), and nova
    attributes per family.
    """

    ORG_POPULATED = {'2': 'member'}

    def setUp(self):
        self.user = User.objects.create_user(
            username='mint-seq-user', email='mint-seq-user@shizuha.com',
            password='pw')

    @staticmethod
    def _resp(payload):
        return MagicMock(status_code=200,
                         json=MagicMock(return_value=payload))

    def _mint(self, *, project_ids, project_roles):
        """One full projection read; returns the ordered outcome labels."""
        responses = [
            self._resp({'memberships': self.ORG_POPULATED}),
            self._resp({'project_ids': project_ids,
                        'project_memberships': project_roles}),
        ]
        with patch('identity.views._admin_req.get', side_effect=responses), \
                patch('identity.views.record_membership_projection_event') as rec:
            _fetch_membership_projection(self.user)
            return [c.args[0] for c in rec.call_args_list]

    def _mint_zero_project(self):
        return self._mint(project_ids=[], project_roles={})

    def _mint_populated(self):
        return self._mint(project_ids=[7], project_roles={'7': 'member'})

    # ---- 1 + 2: the two ordered shapes nova reads ------------------------

    def test_zero_project_identity_records_success_then_authoritative_empty(self):
        """org populated + zero projects -> ('success', 'authoritative_empty')."""
        self.assertEqual(
            self._mint_zero_project(), ['success', 'authoritative_empty'],
        )

    def test_populated_identity_records_success_twice(self):
        """both families populated -> ('success', 'success')."""
        self.assertEqual(self._mint_populated(), ['success', 'success'])

    # ---- 3: the divisor that must not drift ------------------------------

    def test_every_mint_records_exactly_two_events_one_per_family(self):
        for label, recorded in (
            ('zero-project', self._mint_zero_project()),
            ('populated', self._mint_populated()),
        ):
            self.assertEqual(
                len(recorded), 2,
                f'{label} mint recorded {len(recorded)} events, not 2. A mint '
                'records exactly one outcome per membership family; adding a '
                'third fetcher or dropping one silently invalidates the live '
                'burst arithmetic derived from this class.',
            )

    # ---- 4: the totals, computed rather than transcribed -----------------

    def test_burst_of_K_of_each_shape_yields_3K_success_and_K_empty(self):
        """The number @nova's window gate predicts, asserted not narrated.

        K mints of each shape: zero-project contributes 1 success, populated
        contributes 2 -> success = 3K; only zero-project emits the empty label
        -> authoritative_empty = K. Derived here by execution so the value can
        never disagree with the code the way a written formula can.
        """
        K = 4
        recorded = []
        for _ in range(K):
            recorded += self._mint_zero_project()
            recorded += self._mint_populated()

        self.assertEqual(recorded.count('success'), 3 * K)
        self.assertEqual(recorded.count('authoritative_empty'), K)
        self.assertEqual(len(recorded), 4 * K, 'two records per mint, 2K mints')
        # No other label may appear on an all-200 burst; a stray `non_200` or
        # `timeout` here would mean a failure path reached a success fixture.
        self.assertEqual(set(recorded), {'success', 'authoritative_empty'})
