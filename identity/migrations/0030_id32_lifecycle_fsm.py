from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


def backfill_lifecycle_state(apps, schema_editor):
    """Derive lifecycle_state for existing rows from (approval_status, is_active).

    Mirrors identity.lifecycle.derive_lifecycle_state: denied→denied,
    pending→pending, approved+active→active, approved+inactive→deactivated.
    """
    UserProfile = apps.get_model('identity', 'UserProfile')
    UserProfile.objects.filter(approval_status='denied').update(lifecycle_state='denied')
    UserProfile.objects.filter(approval_status='pending').update(lifecycle_state='pending')
    UserProfile.objects.filter(
        approval_status='approved', user__is_active=True,
    ).update(lifecycle_state='active')
    UserProfile.objects.filter(
        approval_status='approved', user__is_active=False,
    ).update(lifecycle_state='deactivated')


class Migration(migrations.Migration):
    """ID-32: lifecycle FSM state + soft-delete tombstones + per-transition audit."""

    dependencies = [
        ('identity', '0029_adminauditevent'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='lifecycle_state',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('pending', 'Pending'), ('active', 'Active'), ('denied', 'Denied'),
                    ('deactivated', 'Deactivated'), ('deleted', 'Deleted'),
                ],
                default='pending',
                db_index=True,
            ),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='deactivated_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='deleted_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.CreateModel(
            name='UserLifecycleAudit',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('actor_id', models.IntegerField(blank=True, help_text='User id that requested the transition (null = system)', null=True)),
                ('from_state', models.CharField(max_length=20)),
                ('to_state', models.CharField(max_length=20)),
                ('reason', models.TextField(blank=True, default='')),
                ('outcome', models.CharField(choices=[('applied', 'Applied'), ('rejected', 'Rejected')], max_length=10)),
                ('created_at', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('user', models.ForeignKey(help_text='Subject of the transition', on_delete=django.db.models.deletion.CASCADE, related_name='lifecycle_audit_rows', to=settings.AUTH_USER_MODEL)),
            ],
            options={'ordering': ['-created_at']},
        ),
        migrations.RunPython(backfill_lifecycle_state, migrations.RunPython.noop),
    ]
