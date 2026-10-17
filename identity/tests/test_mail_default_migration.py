"""Universal managed-Mail catalog/default migration coverage."""
import importlib

from django.apps import apps
from django.contrib.auth import get_user_model
from django.test import TestCase

from identity.models import Tool


migration = importlib.import_module(
    'identity.migrations.0039_enable_mail_default_entitlement'
)
User = get_user_model()


class MailDefaultEntitlementMigrationTests(TestCase):
    def setUp(self):
        self.mail, _ = Tool.objects.update_or_create(
            slug='mail',
            defaults={
                'display_name': 'Mail',
                'is_active': False,
                'is_default_enabled': False,
                'requires_approval': True,
                'requires_superuser': True,
            },
        )
        self.user = User.objects.create_user(
            username='mail-migration-user',
            email='mail-migration-user@example.com',
        )
        self.user.profile.enabled_tools.remove(self.mail)

    def test_forward_aligns_catalog_and_backfills_every_profile(self):
        migration.enable_mail_default_entitlement(apps, None)

        self.mail.refresh_from_db()
        self.assertTrue(self.mail.is_active)
        self.assertTrue(self.mail.is_default_enabled)
        self.assertFalse(self.mail.requires_approval)
        self.assertFalse(self.mail.requires_superuser)
        self.assertTrue(self.user.profile.enabled_tools.filter(slug='mail').exists())

    def test_reverse_does_not_revoke_existing_entitlement(self):
        migration.enable_mail_default_entitlement(apps, None)
        migration.preserve_mail_entitlements_on_reverse(apps, None)

        self.mail.refresh_from_db()
        self.assertFalse(self.mail.is_default_enabled)
        self.assertTrue(self.user.profile.enabled_tools.filter(slug='mail').exists())
