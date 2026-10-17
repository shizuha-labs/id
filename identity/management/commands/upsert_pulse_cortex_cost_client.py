"""Idempotently provision the EVOL-64 Pulse -> Cortex cost-aggregator client."""
import hashlib
import os
import re

from django.core.management.base import BaseCommand, CommandError

from identity.models import OAuthClient


CLIENT_ID = 'pulse-cortex-cost'
SCOPE = 'cortex:usage-by-user.read'
SHA256_HEX_RE = re.compile(r'[0-9a-f]{64}')


def _validated_sha256(value, *, source):
    """Return a canonical SHA-256 verifier or fail without disclosing it."""
    candidate = str(value or '').strip().lower()
    if candidate and not SHA256_HEX_RE.fullmatch(candidate):
        raise CommandError(f'{source} must be a 64-character SHA-256 hex digest')
    return candidate


class Command(BaseCommand):
    help = 'Create/update the Pulse Cortex cost OAuth client without printing secret material.'

    def handle(self, *args, **options):
        configured_hash = _validated_sha256(
            os.environ.get('PULSE_CORTEX_OAUTH_CLIENT_SECRET_SHA256', ''),
            source='PULSE_CORTEX_OAUTH_CLIENT_SECRET_SHA256',
        )
        secret = os.environ.get('PULSE_CORTEX_OAUTH_CLIENT_SECRET', '')
        if not configured_hash and secret:
            configured_hash = hashlib.sha256(secret.encode()).hexdigest()

        existing = OAuthClient.objects.filter(client_id=CLIENT_ID).first()
        preserved_hash = _validated_sha256(
            getattr(existing, 'client_secret_hash', '') if existing else '',
            source='existing pulse-cortex-cost verifier',
        )
        secret_hash = configured_hash or preserved_hash
        if not secret_hash:
            raise CommandError(
                'pulse-cortex-cost is confidential but has no verifier; set '
                'PULSE_CORTEX_OAUTH_CLIENT_SECRET_SHA256 before starting ID'
            )

        client, created = OAuthClient.objects.update_or_create(
            client_id=CLIENT_ID,
            defaults={
                'client_secret_hash': secret_hash,
                'client_name': 'Pulse Cortex Cost Aggregator',
                'redirect_uris': [],
                'grant_types': ['client_credentials'],
                'response_types': [],
                'scope': SCOPE,
                'client_type': OAuthClient.CLIENT_TYPE_CONFIDENTIAL,
                'is_system': True,
            },
        )
        action = 'created' if created else 'updated'
        self.stdout.write(self.style.SUCCESS(
            f'{CLIENT_ID} {action}: scope="{SCOPE}" '
            f'secret_hash_configured={bool(client.client_secret_hash)}'
        ))
