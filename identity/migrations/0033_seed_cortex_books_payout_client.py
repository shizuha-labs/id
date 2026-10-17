"""CTX-404: reserve a migration boundary for the Cortex -> Books M2M client.

Provisioning deliberately happens in the restart-safe management command, not
in this one-shot migration. ID and deploy are released independently, so a
migration must not seed or preserve a verifier before the Secret-backed command
can validate it.
"""

from django.db import migrations


CLIENT_ID = 'cortex-books-payouts'
SCOPE = 'books:cortex-provider-payable.create'


def seed_client(apps, schema_editor):
    # Cross-repo rollouts can deploy ID code before the verifier Secret. Leave
    # both creation and validation to upsert_cortex_books_payout_client, which
    # runs on every restart after migrations and fails loudly on bad material.
    return None


def remove_client(apps, schema_editor):
    OAuthClient = apps.get_model('identity', 'OAuthClient')
    OAuthClient.objects.filter(client_id=CLIENT_ID).delete()


class Migration(migrations.Migration):
    dependencies = [('identity', '0032_id44_canonical_user_identifiers')]
    operations = [migrations.RunPython(seed_client, remove_client)]
