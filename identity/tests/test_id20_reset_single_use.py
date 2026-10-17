"""ID-20 (HLD ID-1 §3.4, acceptance #1): password-reset tokens are single-use.

Locks in the existing enforcement: a token is rejected after its first successful
use (``mark_used`` + ``is_valid``), any other unused token for the user is
invalidated when a reset completes, and the 1h time-box holds. (Single-use was
already implemented; ID-20 acceptance #1 requires the regression test.) The
constant-time non-enumeration (acceptance #2) and per-account+per-IP rate-limiting
(acceptance #3) are separate sub-slices.
"""
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIRequestFactory

from identity.models import PasswordResetToken
from identity.views import PasswordResetConfirmView

User = get_user_model()
_PW = 'Str0ng!Passw0rd#2026'


class ResetSingleUseTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = User.objects.create_user(
            username='resetuser', password='oldpw',
            email='resetuser@example.com', is_active=True,
        )

    def _confirm(self, token_str, pw=_PW):
        req = self.factory.post(
            '/password-reset/confirm/',
            {'token': token_str, 'new_password': pw, 'new_password2': pw},
            format='json',
        )
        return PasswordResetConfirmView.as_view()(req)

    def test_token_rejected_after_first_use(self):
        token = PasswordResetToken.create_for_user(self.user)
        r1 = self._confirm(token.token)
        self.assertEqual(r1.status_code, 200)
        token.refresh_from_db()
        self.assertIsNotNone(token.used_at)  # marked used
        # Reusing the same token must be rejected (single-use).
        r2 = self._confirm(token.token)
        self.assertEqual(r2.status_code, 400)

    def test_other_unused_tokens_invalidated_on_use(self):
        t1 = PasswordResetToken.create_for_user(self.user)
        t2 = PasswordResetToken.create_for_user(self.user)
        self.assertEqual(self._confirm(t1.token).status_code, 200)
        # A different unused token issued before the reset must no longer be valid
        # (password change invalidates outstanding reset tokens).
        t2.refresh_from_db()
        self.assertFalse(t2.is_valid)

    def test_expired_token_rejected(self):
        token = PasswordResetToken.create_for_user(self.user)
        token.expires_at = timezone.now() - timedelta(minutes=1)
        token.save(update_fields=['expires_at'])
        self.assertEqual(self._confirm(token.token).status_code, 400)

    def test_default_expiry_is_one_hour(self):
        before = timezone.now()
        token = PasswordResetToken.create_for_user(self.user)
        delta = token.expires_at - before  # 1h time-box (HLD §3.4)
        self.assertGreater(delta, timedelta(minutes=55))
        self.assertLessEqual(delta, timedelta(hours=1, minutes=1))
