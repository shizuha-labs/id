from django.db import migrations, models


def bound_mail_offline_revocation_lag(apps, schema_editor):
    OAuthClient = apps.get_model('identity', 'OAuthClient')
    OAuthClient.objects.filter(client_name='shizuha-mail').update(
        access_token_ttl_minutes=1,
    )


def restore_default_access_ttl(apps, schema_editor):
    OAuthClient = apps.get_model('identity', 'OAuthClient')
    OAuthClient.objects.filter(client_name='shizuha-mail').update(
        access_token_ttl_minutes=60,
    )


class Migration(migrations.Migration):
    dependencies = [
        ('identity', '0036_alter_userlifecycleevent_event_type_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='oauthclient',
            name='access_token_ttl_minutes',
            field=models.PositiveSmallIntegerField(
                default=60,
                help_text=(
                    'Access-token lifetime for this client. Federated protocols '
                    'that validate JWTs offline should use a short TTL to bound '
                    'revocation lag.'
                ),
            ),
        ),
        migrations.RunPython(
            bound_mail_offline_revocation_lag,
            restore_default_access_ttl,
        ),
    ]
