from collections import defaultdict

from django.conf import settings
from django.db import migrations


def _canon(value):
    return (value or '').strip().casefold()


def _find_conflicts(users, field):
    groups = defaultdict(list)
    for user in users:
        key = _canon(getattr(user, field))
        if key:
            groups[key].append(user.pk)
    return {key: ids for key, ids in groups.items() if len(ids) > 1}


def canonicalize_existing_users(apps, schema_editor):
    app_label, model_name = settings.AUTH_USER_MODEL.split('.')
    User = apps.get_model(app_label, model_name)
    users = list(User.objects.all().only('id', 'username', 'email'))

    username_conflicts = _find_conflicts(users, 'username')
    email_conflicts = _find_conflicts(users, 'email')
    if username_conflicts or email_conflicts:
        details = []
        if username_conflicts:
            details.append(f"username conflicts={username_conflicts}")
        if email_conflicts:
            details.append(f"email conflicts={email_conflicts}")
        raise RuntimeError(
            'ID-44 cannot add canonical user uniqueness until duplicates are resolved: '
            + '; '.join(details)
        )

    for user in users:
        username = _canon(user.username)
        email = _canon(user.email)
        updates = []
        if user.username != username:
            user.username = username
            updates.append('username')
        if user.email != email:
            user.email = email
            updates.append('email')
        if updates:
            user.save(update_fields=updates)


def add_canonical_indexes(apps, schema_editor):
    app_label, model_name = settings.AUTH_USER_MODEL.split('.')
    User = apps.get_model(app_label, model_name)
    user_table = schema_editor.quote_name(User._meta.db_table)
    schema_editor.execute(
        f"CREATE UNIQUE INDEX IF NOT EXISTS identity_user_username_canonical_uniq "
        f"ON {user_table} ((LOWER(TRIM(username)))) "
        f"WHERE username IS NOT NULL AND TRIM(username) <> ''"
    )
    schema_editor.execute(
        f"CREATE UNIQUE INDEX IF NOT EXISTS identity_user_email_canonical_uniq "
        f"ON {user_table} ((LOWER(TRIM(email)))) "
        f"WHERE email IS NOT NULL AND TRIM(email) <> ''"
    )


def drop_canonical_indexes(apps, schema_editor):
    schema_editor.execute('DROP INDEX IF EXISTS identity_user_email_canonical_uniq')
    schema_editor.execute('DROP INDEX IF EXISTS identity_user_username_canonical_uniq')


class Migration(migrations.Migration):
    dependencies = [
        ('identity', '0031_id39_user_lifecycle_outbox'),
    ]

    operations = [
        migrations.RunPython(canonicalize_existing_users, migrations.RunPython.noop),
        migrations.RunPython(add_canonical_indexes, drop_canonical_indexes),
    ]
