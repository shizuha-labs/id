from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('identity', '0041_merge_20260819_0411'),
    ]

    operations = [
        migrations.AddField(
            model_name='pushtoken',
            name='session_sid',
            field=models.CharField(blank=True, db_index=True, default='', max_length=64),
        ),
        migrations.CreateModel(
            name='RevokedSession',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('sid', models.CharField(db_index=True, max_length=64, unique=True)),
                ('revoked_at', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('reason', models.CharField(blank=True, default='logout', max_length=100)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='revoked_sessions', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-revoked_at'],
            },
        ),
    ]
