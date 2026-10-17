from django.db import migrations, models


class Migration(migrations.Migration):
    """
    ID-31: change UserProfile.approval_status default from 'approved' to 'pending'.

    New profiles now fail-safe (pending) unless a creation path explicitly approves
    them. Internal/agent provisioning paths already set 'approved' explicitly;
    registration paths already set 'pending' explicitly — both are unaffected.
    """

    dependencies = [
        ('identity', '0025_userprofile_access_revoked_before'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userprofile',
            name='approval_status',
            field=models.CharField(
                max_length=20,
                choices=[
                    ('approved', 'Approved'),
                    ('pending', 'Pending'),
                    ('denied', 'Denied'),
                ],
                default='pending',
            ),
        ),
    ]
