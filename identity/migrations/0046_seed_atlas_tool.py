"""Make Atlas available for explicit service grants on fresh installations."""
from django.db import migrations


def seed_atlas_tool(apps, schema_editor):
    Tool = apps.get_model('identity', 'Tool')
    # Existing deployments may have configured this service already. Preserve
    # those settings and grants; catalog registration grants no new access.
    Tool.objects.using(schema_editor.connection.alias).get_or_create(
        slug='atlas',
        defaults={
            'display_name': 'Atlas',
            'description': 'Platform architecture and service catalog',
            'icon': 'map',
            'is_active': True,
            'is_default_enabled': False,
            'requires_approval': False,
            'requires_superuser': False,
        },
    )


class Migration(migrations.Migration):
    dependencies = [('identity', '0045_userprofile_token_version')]
    operations = [migrations.RunPython(seed_atlas_tool, migrations.RunPython.noop)]
