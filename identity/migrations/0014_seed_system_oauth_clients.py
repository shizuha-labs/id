"""
Seed well-known system OAuth clients so Claude Code (and other first-party
tools) can use stable client_ids without hitting the dynamic registration
endpoint. These rows cannot be removed by public registration callers
(is_system=True).
"""
from django.db import migrations


SYSTEM_CLIENTS = [
    {
        'client_id': 'shizuha-claude-code',
        'client_name': 'Claude Code CLI',
        'redirect_uris': [
            'http://localhost',
            'http://127.0.0.1',
            'http://localhost/callback',
            'http://127.0.0.1/callback',
        ],
        'grant_types': ['authorization_code', 'refresh_token'],
        'response_types': ['code'],
        'scope': '*',
        'client_type': 'public',
        'is_system': True,
    },
]


def seed_clients(apps, schema_editor):
    OAuthClient = apps.get_model('identity', 'OAuthClient')
    for spec in SYSTEM_CLIENTS:
        OAuthClient.objects.update_or_create(
            client_id=spec['client_id'],
            defaults={k: v for k, v in spec.items() if k != 'client_id'},
        )


def remove_clients(apps, schema_editor):
    OAuthClient = apps.get_model('identity', 'OAuthClient')
    OAuthClient.objects.filter(
        client_id__in=[c['client_id'] for c in SYSTEM_CLIENTS],
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ('identity', '0013_revokedtoken'),
    ]
    operations = [
        migrations.RunPython(seed_clients, remove_clients),
    ]
