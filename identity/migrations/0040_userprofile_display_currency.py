from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('identity', '0039_enable_mail_default_entitlement'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='display_currency',
            field=models.CharField(
                default='USD',
                help_text='Indicative fiat suffix for Hane (USD default). Not a peg.',
                max_length=8,
            ),
        ),
    ]
