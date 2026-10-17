import io
import os
import secrets
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase
from identity.models import UserProfile


class DemoSeedConfigurationTests(TestCase):
    def seed(self, password='', *args):
        output = io.StringIO()
        with patch.dict(os.environ, {'SHIZUHA_DEMO_PASSWORD': password,
                                     'SHIZUHA_DEMO_USERNAME': 'demo-config-test',
                                     'SHIZUHA_DEMO_EMAIL': 'demo@example.test'}):
            call_command('seed_demo_user', *args, stdout=output)
        if password:
            self.assertNotIn(password, output.getvalue())
        return output.getvalue()

    def test_unconfigured_startup_does_not_create_account(self):
        self.seed()
        self.assertFalse(get_user_model().objects.filter(username='demo-config-test').exists())

    def test_configured_seed_creates_approved_nonprivileged_account(self):
        password = secrets.token_urlsafe(24)
        self.seed(password)
        user = get_user_model().objects.get(username='demo-config-test')
        self.assertTrue(user.check_password(password))
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertEqual(UserProfile.objects.get(user=user).approval_status, 'approved')

    def test_repeated_seed_preserves_password_and_access_without_reset_flag(self):
        original = secrets.token_urlsafe(24)
        self.seed(original)
        user = get_user_model().objects.get(username='demo-config-test')
        user.is_active = False
        user.save(update_fields=['is_active'])
        self.seed(secrets.token_urlsafe(24))
        user.refresh_from_db()
        self.assertTrue(user.check_password(original))
        self.assertFalse(user.is_active)

    def test_explicit_reset_uses_deployment_secret_without_logging_it(self):
        self.seed(secrets.token_urlsafe(24))
        replacement = secrets.token_urlsafe(24)
        self.seed(replacement, '--reset-password')
        user = get_user_model().objects.get(username='demo-config-test')
        self.assertTrue(user.check_password(replacement))
