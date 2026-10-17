# ID-21 (HLD 815412d1 §3.6): bind push tokens to their issuing session/refresh family.
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('identity', '0025_userprofile_access_revoked_before'),
    ]

    operations = [
        migrations.AddField(
            model_name='pushtoken',
            name='session_jti',
            field=models.CharField(blank=True, db_index=True, default='', max_length=255),
        ),
    ]
