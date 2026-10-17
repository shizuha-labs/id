"""ORIG-4: seed the forgejo-origin confidential OIDC client.

Registers a system-owned confidential OAuth2/OIDC client that Forgejo uses to
authenticate against shizuha-id via OpenID Connect. The client_id is stable
(`forgejo-origin`) and the callback path is tied to Forgejo's auth-source name
`shizuha-id`.

Secret management: the client secret itself is never stored in source.
Operators can provide either FORGEJO_ORIGIN_OIDC_CLIENT_SECRET or the
precomputed FORGEJO_ORIGIN_OIDC_CLIENT_SECRET_SHA256 while applying this
migration. If neither is set, any existing hash is preserved and new rows are
created with a blank hash; run the management command before activating the
Forgejo auth source.
"""
import hashlib
import os

from django.db import migrations


CLIENT_ID = 'forgejo-origin'
REDIRECT_URI = 'https://origin.shizuha/user/oauth2/shizuha-id/callback'
SCOPE = 'openid profile email groups'


def _configured_secret_hash(existing_hash: str = '') -> str:
    direct_hash = os.environ.get('FORGEJO_ORIGIN_OIDC_CLIENT_SECRET_SHA256', '').strip()
    if direct_hash:
        return direct_hash

    # Back-compat with the original PR draft env name, while preferring the
    # ORIG-scoped name above for new deployments.
    secret = (
        os.environ.get('FORGEJO_ORIGIN_OIDC_CLIENT_SECRET')
        or os.environ.get('FORGEJO_OIDC_CLIENT_SECRET')
        or ''
    )
    if secret:
        return hashlib.sha256(secret.encode()).hexdigest()
    return existing_hash


def seed_client(apps, schema_editor):
    OAuthClient = apps.get_model('identity', 'OAuthClient')
    existing = OAuthClient.objects.filter(client_id=CLIENT_ID).first()
    OAuthClient.objects.update_or_create(
        client_id=CLIENT_ID,
        defaults={
            'client_secret_hash': _configured_secret_hash(
                getattr(existing, 'client_secret_hash', '') if existing else ''
            ),
            'client_name': 'Shizuha Origin Forgejo',
            'redirect_uris': [REDIRECT_URI],
            'grant_types': ['authorization_code', 'refresh_token'],
            'response_types': ['code'],
            'scope': SCOPE,
            'client_type': 'confidential',
            'is_system': True,
        },
    )


def remove_client(apps, schema_editor):
    OAuthClient = apps.get_model('identity', 'OAuthClient')
    OAuthClient.objects.filter(client_id=CLIENT_ID).delete()


class Migration(migrations.Migration):
    dependencies = [
        ('identity', '0019_webauthn_stepup'),
    ]
    operations = [
        migrations.RunPython(seed_client, remove_client),
    ]
