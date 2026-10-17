"""PLAT-5731: mailbox_address_for_user is not injective — colliding local parts
must never both hold a signed mail identity.

Regression: ``alice`` and ``alice@gmail.com`` are distinct raw usernames that
both derive ``alice@shizuha.com``. The guard must be applied on the DERIVED
mailbox local part at both derivation sites (``mailbox_address_for_user`` and
``_unique_username``), not on the raw username.
"""
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.core.cache import caches
from django.test import TestCase, override_settings

from identity.lifecycle import (
    mailbox_address_for_user,
    mailbox_localpart_for_username,
    mailbox_localpart_taken,
)
from identity.models import UserProfile

User = get_user_model()

_TEST_CACHES = {
    'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'},
    'oauth_shared': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
                     'LOCATION': 'oauth-shared-test'},
}


def _make_user(username, email=None):
    return User.objects.create_user(
        username=username,
        email=email or f'{username}@example.com',
        password='pw',
    )


@override_settings(CACHES=_TEST_CACHES)
class MailboxLocalPartTests(TestCase):
    def test_localpart_derivation_is_not_injective(self):
        # Both shapes derive the same local part — this is the defect's premise.
        self.assertEqual(mailbox_localpart_for_username('alice'), 'alice')
        self.assertEqual(mailbox_localpart_for_username('alice@gmail.com'), 'alice')
        self.assertEqual(mailbox_localpart_for_username('Alice@Yahoo.com'), 'alice')

    def test_mailbox_address_uses_derived_localpart(self):
        with patch.dict('os.environ', {'SHIZUHA_MAIL_DOMAIN': 'shizuha.com'}, clear=False):
            self.assertEqual(
                mailbox_address_for_user(_make_user('alice@gmail.com')),
                'alice@shizuha.com',
            )


@override_settings(CACHES=_TEST_CACHES)
class MailboxLocalPartTakenTests(TestCase):
    def test_plain_username_collision(self):
        _make_user('alice')
        self.assertTrue(mailbox_localpart_taken('alice'))
        self.assertTrue(mailbox_localpart_taken('Alice'))
        self.assertFalse(mailbox_localpart_taken('bob'))

    def test_at_containing_username_collision(self):
        # 'alice@gmail.com' derives local part 'alice' — the raw username__iexact
        # check alone would MISS this (alice != alice@gmail.com).
        _make_user('alice@gmail.com')
        self.assertTrue(mailbox_localpart_taken('alice'))
        self.assertFalse(mailbox_localpart_taken('bob'))

    def test_exclude_self_does_not_report_own_collision(self):
        user = _make_user('alice')
        self.assertFalse(mailbox_localpart_taken('alice', exclude_user_id=user.id))


@override_settings(CACHES=_TEST_CACHES)
class UniqueUsernameConsultsMailboxGuardTests(TestCase):
    def test_unique_username_avoids_derived_mailbox_collision(self):
        from identity.views import _unique_username
        # Existing 'alice@gmail.com' derives local part 'alice'.
        _make_user('alice@gmail.com')
        # A new seed 'alice' must NOT reuse local part 'alice' — it must pick a
        # distinct username whose derived mailbox does not collide.
        candidate = _unique_username('alice')
        self.assertNotEqual(candidate, 'alice')
        self.assertFalse(mailbox_localpart_taken(candidate))
        # Positive control: an unused seed keeps its natural name.
        self.assertEqual(_unique_username('bob'), 'bob')

    def test_google_signup_never_derives_one_mailbox(self):
        """Live sequence from the acceptance: existing alice@gmail.com + Google
        signup for alice@anywhere.com must NOT create two accounts deriving
        alice@shizuha.com."""
        from identity.tests.test_google_signin import (
            GOOGLE_ENV, _google_settings, _mock_google,
        )
        from identity.views import _admin_req
        _make_user('alice@gmail.com')

        caches['oauth_shared'].clear()
        caches['oauth_shared'].set('google_oauth_state:S1', {'continue': '/cortex'}, timeout=600)
        token_resp, userinfo_resp = _mock_google(email='alice@anywhere.com')
        with patch.dict('os.environ', GOOGLE_ENV, clear=False), \
             override_settings(**_google_settings()), \
             patch('identity.views._admin_req') as req:
            req.post.return_value = token_resp
            req.get.return_value = userinfo_resp
            resp = self.client.get('/api/auth/social/callback/?code=abc&state=S1')
            self.assertEqual(resp.status_code, 302, resp.content)

        # The new account's derived mailbox must differ from alice@shizuha.com.
        new_user = User.objects.get(email='alice@anywhere.com')
        self.assertNotEqual(new_user.username, 'alice')
        self.assertNotEqual(mailbox_address_for_user(new_user), 'alice@shizuha.com')
        # And no two accounts derive the same mailbox local part.
        self.assertEqual(
            User.objects.filter(username__iexact='alice').count()
            + User.objects.filter(username__iregex=r'^alice@').count(),
            1,
        )
