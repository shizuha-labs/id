from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('identity', '0003_seed_services'),
    ]

    operations = [
        migrations.CreateModel(
            name='ServiceAccessRequest',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('organization_id', models.IntegerField(blank=True, null=True)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('approved', 'Approved'), ('denied', 'Denied')], default='pending', max_length=20)),
                ('reason', models.TextField(blank=True)),
                ('reviewed_by_id', models.IntegerField(blank=True, null=True)),
                ('reviewed_at', models.DateTimeField(blank=True, null=True)),
                ('review_note', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('tool', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='access_requests', to='identity.tool')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='service_access_requests', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]
