"""Google Sign-In (server-side OAuth) — state, callback, find-or-create, handoff."""
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.core.cache import caches
from django.test import TestCase, override_settings

from identity.models import UserProfile

User = get_user_model()

# The views read OAuth state/handoff from the shared 'oauth_shared' cache
# (Redis in prod); point it at locmem for tests (single process = shared).
_TEST_CACHES = {
    'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'},
    'oauth_shared': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
                     'LOCATION': 'oauth-shared-test'},
}


def _oc():
    return caches['oauth_shared']


GOOGLE_ENV = {
    'GOOGLE_CLIENT_ID': 'test-client.apps.googleusercontent.com',
    'GOOGLE_CLIENT_SECRET': 'test-secret',
    'GOOGLE_REDIRECT_URI': 'https://shizuha.com/id/api/auth/social/callback/',
    'GOOGLE_SPA_CALLBACK_URL': 'https://shizuha.com/id/auth/google',
}


def _google_settings(**over):
    prov = {'google': {'APP': {'client_id': GOOGLE_ENV['GOOGLE_CLIENT_ID'],
                               'secret': GOOGLE_ENV['GOOGLE_CLIENT_SECRET']}}}
    return dict(SOCIALACCOUNT_PROVIDERS=prov, **over)


@override_settings(CACHES=_TEST_CACHES)
class GoogleAuthUrlTests(TestCase):
    def setUp(self):
        caches['oauth_shared'].clear()

    @patch.dict('os.environ', GOOGLE_ENV, clear=False)
    @override_settings(**_google_settings())
    def test_authorize_url_has_state_and_stashes_continue(self):
        resp = self.client.get('/api/auth/social/google/?continue=/cortex')
        self.assertEqual(resp.status_code, 200, resp.content)
        url = resp.data['url']
        self.assertIn('accounts.google.com/o/oauth2/v2/auth', url)
        self.assertIn('state=', url)
        self.assertIn('client_id=test-client', url)
        # state row must exist and carry the continue target
        import re
        state = re.search(r'state=([^&]+)', url).group(1)
        self.assertEqual(_oc().get(f'google_oauth_state:{state}'), {'continue': '/cortex'})

    @override_settings(SOCIALACCOUNT_PROVIDERS={'google': {'APP': {'client_id': ''}}})
    @patch.dict('os.environ', {'GOOGLE_CLIENT_ID': ''}, clear=False)
    def test_not_configured_501(self):
        resp = self.client.get('/api/auth/social/google/')
        self.assertEqual(resp.status_code, 501)


def _mock_google(email='newuser@gmail.com', verified=True, given='New', family='User'):
    """Patch the two outbound Google calls (token exchange + userinfo)."""
    token_resp = MagicMock(status_code=200)
    token_resp.json.return_value = {'access_token': 'ya29.fake'}
    userinfo_resp = MagicMock(status_code=200)
    userinfo_resp.json.return_value = {
        'email': email, 'email_verified': verified,
        'given_name': given, 'family_name': family, 'sub': '12345',
    }
    return token_resp, userinfo_resp


@override_settings(CACHES=_TEST_CACHES)
class GoogleCallbackTests(TestCase):
    def setUp(self):
        caches['oauth_shared'].clear()

    def _seed_state(self, continue_url='/cortex'):
        _oc().set('google_oauth_state:S1', {'continue': continue_url}, timeout=600)

    @patch.dict('os.environ', GOOGLE_ENV, clear=False)
    @override_settings(**_google_settings())
    @patch('identity.views._admin_req')
    def test_new_user_created_active_and_handoff_issued(self, req):
        self._seed_state()
        token_resp, userinfo_resp = _mock_google(email='alice@gmail.com')
        req.post.return_value = token_resp
        req.get.return_value = userinfo_resp

        resp = self.client.get('/api/auth/social/callback/?code=abc&state=S1')
        self.assertEqual(resp.status_code, 302)
        self.assertIn('shizuha.com/id/auth/google', resp['Location'])
        self.assertIn('handoff=', resp['Location'])
        self.assertIn('continue=%2Fcortex', resp['Location'])

        user = User.objects.get(email='alice@gmail.com')
        self.assertTrue(user.is_active)  # auto-approved (verified email)
        self.assertEqual(user.profile.approval_status, 'approved')
        self.assertFalse(user.has_usable_password())
        # state is single-use
        self.assertIsNone(_oc().get('google_oauth_state:S1'))

    @patch.dict('os.environ', GOOGLE_ENV, clear=False)
    @override_settings(**_google_settings())
    @patch('identity.views._admin_req')
    def test_existing_email_links_not_duplicates(self, req):
        existing = User.objects.create(username='bob', email='bob@gmail.com', is_active=True)
        UserProfile.objects.get_or_create(user=existing)
        self._seed_state()
        token_resp, userinfo_resp = _mock_google(email='bob@gmail.com')
        req.post.return_value = token_resp
        req.get.return_value = userinfo_resp

        resp = self.client.get('/api/auth/social/callback/?code=abc&state=S1')
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(User.objects.filter(email='bob@gmail.com').count(), 1)

    @patch.dict('os.environ', dict(GOOGLE_ENV, GOOGLE_SIGNUP_AUTO_APPROVE='0'), clear=False)
    @override_settings(**_google_settings())
    @patch('identity.views._admin_req')
    def test_auto_approve_off_lands_pending(self, req):
        self._seed_state()
        token_resp, userinfo_resp = _mock_google(email='carol@gmail.com')
        req.post.return_value = token_resp
        req.get.return_value = userinfo_resp

        resp = self.client.get('/api/auth/social/callback/?code=abc&state=S1')
        self.assertEqual(resp.status_code, 302)
        self.assertIn('pending=1', resp['Location'])
        user = User.objects.get(email='carol@gmail.com')
        self.assertFalse(user.is_active)

    @patch.dict('os.environ', GOOGLE_ENV, clear=False)
    @override_settings(**_google_settings())
    @patch('identity.views._admin_req')
    def test_unverified_email_rejected(self, req):
        self._seed_state()
        token_resp, userinfo_resp = _mock_google(email='mallory@gmail.com', verified=False)
        req.post.return_value = token_resp
        req.get.return_value = userinfo_resp

        resp = self.client.get('/api/auth/social/callback/?code=abc&state=S1')
        self.assertEqual(resp.status_code, 302)
        self.assertIn('error=', resp['Location'])
        self.assertFalse(User.objects.filter(email='mallory@gmail.com').exists())

    def test_bad_state_rejected(self):
        resp = self.client.get('/api/auth/social/callback/?code=abc&state=NOPE')
        self.assertEqual(resp.status_code, 302)
        self.assertIn('error=', resp['Location'])


@override_settings(CACHES=_TEST_CACHES)
class SocialHandoffTests(TestCase):
    def setUp(self):
        caches['oauth_shared'].clear()

    @patch.dict('os.environ', GOOGLE_ENV, clear=False)
    @override_settings(**_google_settings())
    @patch('identity.views._admin_req')
    def test_handoff_returns_tokens_once_rs256(self, req):
        _oc().set('google_oauth_state:S1', {'continue': ''}, timeout=600)
        token_resp, userinfo_resp = _mock_google(email='dave@gmail.com')
        req.post.return_value = token_resp
        req.get.return_value = userinfo_resp
        cb = self.client.get('/api/auth/social/callback/?code=abc&state=S1')
        import re
        handoff = re.search(r'handoff=([^&]+)', cb['Location']).group(1)

        resp = self.client.post('/api/auth/social/handoff/', {'handoff': handoff})
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertIn('access', resp.data['tokens'])
        self.assertEqual(resp.data['user']['email'], 'dave@gmail.com')
        # RS256 header
        import base64, json
        h = resp.data['tokens']['access'].split('.')[0]
        alg = json.loads(base64.urlsafe_b64decode(h + '=' * (-len(h) % 4)))['alg']
        self.assertEqual(alg, 'RS256')
        # single-use
        resp2 = self.client.post('/api/auth/social/handoff/', {'handoff': handoff})
        self.assertEqual(resp2.status_code, 400)

    def test_bad_handoff_rejected(self):
        resp = self.client.post('/api/auth/social/handoff/', {'handoff': 'nope'})
        self.assertEqual(resp.status_code, 400)
