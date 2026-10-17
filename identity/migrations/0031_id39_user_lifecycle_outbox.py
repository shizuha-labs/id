# Generated for ID-39 user lifecycle transactional outbox
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('identity', '0030_id32_lifecycle_fsm'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserLifecycleEvent',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('event_type', models.CharField(choices=[('user.deactivated', 'User deactivated'), ('user.deleted', 'User deleted'), ('user.reactivated', 'User reactivated')], db_index=True, max_length=40)),
                ('user_id', models.IntegerField(db_index=True)),
                ('user_email', models.EmailField(blank=True, default='', max_length=254)),
                ('user_username', models.CharField(blank=True, default='', max_length=150)),
                ('from_state', models.CharField(max_length=20)),
                ('to_state', models.CharField(max_length=20)),
                ('reason', models.TextField(blank=True, default='')),
                ('payload', models.JSONField(blank=True, default=dict)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('publishing', 'Publishing'), ('published', 'Published'), ('failed', 'Failed')], db_index=True, default='pending', max_length=20)),
                ('attempts', models.PositiveIntegerField(default=0)),
                ('next_attempt_at', models.DateTimeField(blank=True, db_index=True, null=True)),
                ('last_error', models.TextField(blank=True, default='')),
                ('published_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'ordering': ['created_at'],
                'indexes': [models.Index(fields=['status', 'next_attempt_at', 'created_at'], name='identity_us_status_112872_idx'), models.Index(fields=['event_type', 'user_id'], name='identity_us_event_t_c4d42b_idx')],
            },
        ),
    ]
