from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('identity', '0024_userprofile_service_grants_role'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='access_revoked_before',
            field=models.DateTimeField(
                blank=True,
                db_index=True,
                null=True,
                help_text=(
                    'User-level access-token cutoff (ID-13). Access tokens for this user '
                    'with iat <= this timestamp are rejected. Bumped on logout / password-change.'
                ),
            ),
        ),
    ]
