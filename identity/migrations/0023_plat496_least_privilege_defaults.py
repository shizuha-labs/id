"""PLAT-496 / SEC-5: make new-user defaults HIVE-only (+ Account).

Paid claw launch containment: the catalog's default-enabled set must not grant
new signups Pulse/Wiki/Admin/etc. by accident. Existing users keep their
current enabled_tools M2M grants; this migration only changes the Tool catalog
flags used for future grants. The legacy `agent` Tool slug is removed after
confirming nobody holds it.
"""
from django.db import migrations


DEFAULT_SLUGS = {'id', 'hive'}
LEGACY_AGENT_SLUG = 'agent'

HIVE_DEFAULTS = {
    'display_name': 'Hive',
    'description': 'Your AI assistants and user-owned claws',
    'icon': 'bot',
    'minimum_tier': 'free',
    'is_active': True,
    'is_default_enabled': True,
    'requires_approval': False,
    'requires_superuser': False,
}

ID_DEFAULTS = {
    'display_name': 'Account',
    'description': 'Identity and account management',
    'icon': 'user',
    'minimum_tier': 'free',
    'is_active': True,
    'is_default_enabled': True,
    'requires_approval': False,
    'requires_superuser': False,
}

# The broad pre-SEC-5 default set from 0003_seed_services. Reverse restores the
# catalog flags only; it does not remove/alter per-user grants.
PRE_SEC5_DEFAULT_SLUGS = {
    'admin', 'id', 'pulse', 'notes', 'mail', 'time', 'connect', 'wiki',
    'finance', 'books', 'inventory', 'hr', 'home',
}


AGENT_DEFAULTS = {
    'display_name': 'Agent',
    'description': 'AI employee service',
    'icon': 'cpu',
    'minimum_tier': 'free',
    'is_active': True,
    'is_default_enabled': False,
    'requires_approval': True,
    'requires_superuser': False,
}


def apply_least_privilege_defaults(apps, schema_editor):
    Tool = apps.get_model('identity', 'Tool')
    UserProfile = apps.get_model('identity', 'UserProfile')

    Tool.objects.update_or_create(slug='hive', defaults=HIVE_DEFAULTS)
    Tool.objects.update_or_create(slug='id', defaults=ID_DEFAULTS)

    Tool.objects.exclude(slug__in=DEFAULT_SLUGS).update(is_default_enabled=False)

    agent_holders = UserProfile.objects.filter(
        enabled_tools__slug=LEGACY_AGENT_SLUG,
    ).distinct().count()
    if agent_holders:
        raise RuntimeError(
            f"Refusing to delete legacy Tool slug 'agent': {agent_holders} profile(s) still hold it"
        )
    Tool.objects.filter(slug=LEGACY_AGENT_SLUG).delete()


def restore_pre_sec5_defaults(apps, schema_editor):
    Tool = apps.get_model('identity', 'Tool')

    Tool.objects.update_or_create(slug=LEGACY_AGENT_SLUG, defaults=AGENT_DEFAULTS)
    Tool.objects.filter(slug__in=PRE_SEC5_DEFAULT_SLUGS).update(is_default_enabled=True)
    Tool.objects.exclude(slug__in=PRE_SEC5_DEFAULT_SLUGS).update(is_default_enabled=False)


class Migration(migrations.Migration):
    dependencies = [
        ('identity', '0022_login_2fa_recovery_codes'),
    ]

    operations = [
        migrations.RunPython(apply_least_privilege_defaults, restore_pre_sec5_defaults),
    ]
