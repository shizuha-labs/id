"""Upsert the Forgejo Origin OIDC client without printing secret material."""
import hashlib
import os

from django.core.management.base import BaseCommand, CommandError

from identity.models import OAuthClient


CLIENT_ID = 'forgejo-origin'
REDIRECT_URI = 'https://origin.shizuha/user/oauth2/shizuha-id/callback'
SCOPE = 'openid profile email groups'


class Command(BaseCommand):
    help = 'Create/update the Forgejo Origin confidential OIDC client.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--secret-env-var',
            default='FORGEJO_ORIGIN_OIDC_CLIENT_SECRET',
            help='Environment variable containing the client secret (not printed).',
        )
        parser.add_argument(
            '--secret-sha256-env-var',
            default='FORGEJO_ORIGIN_OIDC_CLIENT_SECRET_SHA256',
            help='Environment variable containing a precomputed secret SHA-256 hash.',
        )
        parser.add_argument(
            '--allow-empty-secret-hash',
            action='store_true',
            help='Permit creating the confidential client before the secret is provisioned.',
        )

    def handle(self, *args, **options):
        secret_hash = (os.environ.get(options['secret_sha256_env_var']) or '').strip()
        if not secret_hash:
            secret = os.environ.get(options['secret_env_var']) or ''
            if secret:
                secret_hash = hashlib.sha256(secret.encode()).hexdigest()

        if not secret_hash and not options['allow_empty_secret_hash']:
            raise CommandError(
                'Forgejo Origin OIDC secret is not configured; set '
                f"{options['secret_env_var']} or {options['secret_sha256_env_var']} "
                'or pass --allow-empty-secret-hash for pre-provisioning.'
            )

        defaults = {
            'client_name': 'Shizuha Origin Forgejo',
            'redirect_uris': [REDIRECT_URI],
            'grant_types': ['authorization_code', 'refresh_token'],
            'response_types': ['code'],
            'scope': SCOPE,
            'client_type': OAuthClient.CLIENT_TYPE_CONFIDENTIAL,
            'is_system': True,
        }
        # Only write the secret hash when a new secret is actually being
        # provisioned. Otherwise an idempotent re-run (no secret env set, e.g.
        # --allow-empty-secret-hash) would overwrite the stored hash with '',
        # breaking subsequent client-secret auth (rei cycle-1 P2). Omitting the
        # key preserves the existing hash on update; on create the field default
        # ('') applies for the pre-provisioning case.
        if secret_hash:
            defaults['client_secret_hash'] = secret_hash

        client, created = OAuthClient.objects.update_or_create(
            client_id=CLIENT_ID,
            defaults=defaults,
        )
        action = 'created' if created else 'updated'
        configured = bool(client.client_secret_hash)
        self.stdout.write(
            self.style.SUCCESS(
                f'{CLIENT_ID} {action}: redirect_uri={REDIRECT_URI} '
                f'scope="{SCOPE}" secret_hash_configured={configured}'
            )
        )
