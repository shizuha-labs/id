"""Add unique constraint to auth_user.email field.

Django's default User model has email as non-unique. Since shizuha-id is the
central identity provider and allauth already enforces ACCOUNT_UNIQUE_EMAIL=True
at the application level, this migration adds the database-level constraint to
prevent duplicates from bypassing application validation.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('identity', '0009_seed_oracle_service'),
    ]

    operations = [
        migrations.RunSQL(
            sql='ALTER TABLE auth_user ADD CONSTRAINT auth_user_email_unique UNIQUE (email);',
            reverse_sql='ALTER TABLE auth_user DROP CONSTRAINT auth_user_email_unique;',
        ),
    ]
