"""Align the Tool catalog and existing profiles with universal managed Mail.

Runtime service reconciliation already treats Mail as an identity-owned
baseline capability for both humans and agents.  Keep the catalog's documented
"default for new users" flag consistent and add the entitlement to every
existing profile during migration so access does not depend on a later deploy
hook.
"""
from django.db import migrations


MAIL_SLUG = 'mail'


def enable_mail_default_entitlement(apps, schema_editor):
    Tool = apps.get_model('identity', 'Tool')
    UserProfile = apps.get_model('identity', 'UserProfile')

    updated = Tool.objects.filter(slug=MAIL_SLUG).update(
        is_active=True,
        is_default_enabled=True,
        requires_approval=False,
        requires_superuser=False,
    )
    if updated != 1:
        raise RuntimeError("The seeded Mail Tool must resolve to exactly one row")

    mail = Tool.objects.get(slug=MAIL_SLUG)
    for profile in UserProfile.objects.all().iterator():
        profile.enabled_tools.add(mail)


def preserve_mail_entitlements_on_reverse(apps, schema_editor):
    Tool = apps.get_model('identity', 'Tool')
    # Before this migration, PLAT-496 kept Mail out of the catalog default set.
    # Restore that flag only; never revoke user entitlements during rollback.
    Tool.objects.filter(slug=MAIL_SLUG).update(is_default_enabled=False)


class Migration(migrations.Migration):
    dependencies = [
        ('identity', '0038_promote_configured_mail_oauth_client'),
    ]
    operations = [
        migrations.RunPython(
            enable_mail_default_entitlement,
            preserve_mail_entitlements_on_reverse,
        ),
    ]
