"""Regression coverage for MAIL-73/Mail delegated-client provisioning."""
from importlib import import_module

from django.apps import apps
from django.test import TestCase, override_settings

from identity.models import OAuthClient


migration = import_module(
    'identity.migrations.0038_promote_configured_mail_oauth_client'
)


class Mail74ClientProvisioningTests(TestCase):
    def _client(self, client_id, *, name='shizuha-mail'):
        return OAuthClient.objects.create(
            client_id=client_id,
            client_name=name,
            redirect_uris=['https://mail.example/callback'],
            grant_types=['authorization_code', 'refresh_token'],
            response_types=['code'],
            scope='openid profile email mail',
            client_type='confidential',
            is_system=False,
        )

    @override_settings(SHIZUHA_MAIL_OAUTH_CLIENT_ID='configured-mail-client')
    def test_promotes_only_immutable_configured_client_id(self):
        configured = self._client('configured-mail-client')
        spoof = self._client('spoofed-mail-client')

        migration.promote_configured_mail_client(apps, None)

        configured.refresh_from_db()
        spoof.refresh_from_db()
        self.assertTrue(configured.is_system)
        self.assertFalse(spoof.is_system)

    @override_settings(SHIZUHA_MAIL_OAUTH_CLIENT_ID='missing-mail-client')
    def test_missing_configured_client_fails_deploy_closed(self):
        with self.assertRaisesRegex(RuntimeError, 'exactly one OAuthClient'):
            migration.promote_configured_mail_client(apps, None)

    @override_settings(SHIZUHA_MAIL_OAUTH_CLIENT_ID='')
    def test_unconfigured_isolated_database_is_noop(self):
        migration.promote_configured_mail_client(apps, None)
