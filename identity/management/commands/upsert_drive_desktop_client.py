"""Upsert the Drive Desktop public system OAuth client (DRV-106).

The desktop client is a pre-provisioned PUBLIC client: fixed client id, no
client secret, authorization_code + refresh_token grants, response type
``code``, and least scopes. Dynamic self-registration is not an accepted
release dependency (DRV-104 HLD v2.5 §7).

The client enforces PKCE S256-only and a loopback redirect allowlist
(127.0.0.1 and [::1], any ephemeral port) — see oauth_views for the
enforcement that keys off ``is_drive_desktop``.
"""
from django.core.management.base import BaseCommand

from identity.models import OAuthClient


CLIENT_ID = 'drive-desktop'
SCOPE = 'drive:files.read drive:files.write profile'
REDIRECT_URIS = [
    'http://127.0.0.1',
    'http://[::1]',
]


class Command(BaseCommand):
    help = 'Create/update the Drive Desktop public system OAuth client (DRV-106).'

    def handle(self, *args, **options):
        defaults = {
            'client_name': 'Shizuha Drive for Desktop',
            'redirect_uris': REDIRECT_URIS,
            'grant_types': ['authorization_code', 'refresh_token'],
            'response_types': ['code'],
            'scope': SCOPE,
            'client_type': OAuthClient.CLIENT_TYPE_PUBLIC,
            'is_system': True,
            'access_token_ttl_minutes': 60,
        }
        client, created = OAuthClient.objects.update_or_create(
            client_id=CLIENT_ID,
            defaults=defaults,
        )
        action = 'created' if created else 'updated'
        self.stdout.write(
            self.style.SUCCESS(
                f'{CLIENT_ID} {action}: public system client, '
                f'grants={client.grant_types} scope="{SCOPE}" '
                f'redirects={REDIRECT_URIS}'
            )
        )
