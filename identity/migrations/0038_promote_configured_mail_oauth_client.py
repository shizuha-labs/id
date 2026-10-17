"""Promote the immutable configured Mail OAuth client to a system client.

MAIL-74 pins token exchange to ``SHIZUHA_MAIL_OAUTH_CLIENT_ID`` and rejects
non-system clients.  The production Mail client predates ``is_system`` and was
therefore left non-system when the exchange endpoint shipped.  Resolve only the
configured immutable client id; never select by the public, non-unique display
name.
"""
from django.conf import settings
from django.db import migrations


def promote_configured_mail_client(apps, schema_editor):
    client_id = (getattr(settings, 'SHIZUHA_MAIL_OAUTH_CLIENT_ID', '') or '').strip()
    if not client_id:
        # Some isolated test/dev databases do not provision Mail OAuth at all.
        return

    OAuthClient = apps.get_model('identity', 'OAuthClient')
    updated = OAuthClient.objects.filter(client_id=client_id).update(is_system=True)
    if updated != 1:
        raise RuntimeError(
            'Configured SHIZUHA_MAIL_OAUTH_CLIENT_ID must resolve to exactly one OAuthClient'
        )


def noop_reverse(apps, schema_editor):
    # Never demote a first-party system client during rollback; doing so would
    # reopen the production fail-closed outage fixed by this migration.
    pass


class Migration(migrations.Migration):
    dependencies = [
        ('identity', '0037_oauthclient_access_token_ttl'),
    ]
    operations = [
        migrations.RunPython(promote_configured_mail_client, noop_reverse),
    ]
