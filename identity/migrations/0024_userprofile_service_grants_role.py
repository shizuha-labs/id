from django.db import migrations, models


class Migration(migrations.Migration):
    """ID-12: add service_grants_role field to UserProfile for declarative grant reconciliation."""

    dependencies = [
        ('identity', '0023_plat496_least_privilege_defaults'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='service_grants_role',
            field=models.CharField(
                blank=True,
                db_index=True,
                help_text='Agent role for declarative grant reconciliation (SCLI-45 / ID-12).',
                max_length=50,
                null=True,
            ),
        ),
    ]
