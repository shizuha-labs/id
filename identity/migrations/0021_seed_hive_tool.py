"""
HIVE-67 (E2 of HIVE-59): Seed the `hive` default Tool row and backfill
all existing UserProfile rows.

Forward:
  1. update_or_create Tool(slug='hive', is_default_enabled=True, ...) so
     every *new* user's profile signal already picks it up automatically.
  2. Add the tool to every existing UserProfile.enabled_tools (idempotent —
     ManyToManyField.add is a no-op for already-present entries), so existing
     users get the same entitlement without requiring a re-login or manual op.

Reverse:
  Delete the Tool row.  Django removes the M2M through-table rows
  automatically when the Tool FK target is deleted.
"""
from django.db import migrations


HIVE_TOOL_SLUG = 'hive'

HIVE_TOOL_DEFAULTS = {
    'display_name': 'Hive — your AI assistant',
    'is_active': True,
    'is_default_enabled': True,
    'requires_approval': False,
    'requires_superuser': False,
}


def seed_hive_tool(apps, schema_editor):
    Tool = apps.get_model('identity', 'Tool')
    UserProfile = apps.get_model('identity', 'UserProfile')

    hive_tool, _ = Tool.objects.update_or_create(
        slug=HIVE_TOOL_SLUG,
        defaults=HIVE_TOOL_DEFAULTS,
    )

    # Backfill all existing profiles.  add() is idempotent (skips duplicates)
    # so re-running the migration forward is safe.  Iterating profiles is fine
    # for startup-scale user counts; a batch path can be added later if needed.
    for profile in UserProfile.objects.all():
        profile.enabled_tools.add(hive_tool)


def remove_hive_tool(apps, schema_editor):
    Tool = apps.get_model('identity', 'Tool')
    # Deleting the Tool row cascades to the M2M through-table, so all
    # UserProfile.enabled_tools references are cleaned up automatically.
    Tool.objects.filter(slug=HIVE_TOOL_SLUG).delete()


class Migration(migrations.Migration):
    dependencies = [
        ('identity', '0020_seed_forgejo_origin_oidc_client'),
    ]

    operations = [
        migrations.RunPython(seed_hive_tool, remove_hive_tool),
    ]
