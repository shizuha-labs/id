"""
Seed the Oracle service into the Tool model.
"""
from django.db import migrations


def seed_oracle(apps, schema_editor):
    Tool = apps.get_model('identity', 'Tool')
    Tool.objects.update_or_create(
        slug='oracle',
        defaults={
            'display_name': 'Oracle',
            'description': 'AI-powered predictions and forecasting',
            'icon': 'eye',
            'minimum_tier': 'free',
            'is_active': True,
            'is_default_enabled': False,
            'requires_approval': True,
            'requires_superuser': False,
        }
    )


def unseed_oracle(apps, schema_editor):
    Tool = apps.get_model('identity', 'Tool')
    Tool.objects.filter(slug='oracle').delete()


class Migration(migrations.Migration):

    dependencies = [
        ('identity', '0008_alter_userprofile_approval_note'),
    ]

    operations = [
        migrations.RunPython(seed_oracle, unseed_oracle),
    ]
