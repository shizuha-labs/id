from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('identity', '0033_seed_cortex_books_payout_client')]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='ownership_class',
            field=models.CharField(
                blank=True,
                db_index=True,
                default='',
                help_text='System ownership policy; personal_default_member identities cannot be claimed or reassigned.',
                max_length=40,
            ),
        ),
    ]
