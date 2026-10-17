"""CTX-168: seed the `cortex-qa` group.

Members of this group receive a `groups: ["cortex-qa"]` claim in their
AgentAccessToken (see identity.views._populate_standard_claims). Cortex's
IsQAReadOnly permission (CTX-218) grants read-only access to /v1/admin/nodes
and /v1/admin/backends to any token carrying `cortex-qa` in `groups`.

This migration only creates the group (idempotent). Membership (e.g. adding
the QA agent) is operational data applied per environment, not baked into the
schema, so no specific user is referenced here.
"""
from django.db import migrations


def create_cortex_qa_group(apps, schema_editor):
    Group = apps.get_model('auth', 'Group')
    Group.objects.get_or_create(name='cortex-qa')


def remove_cortex_qa_group(apps, schema_editor):
    Group = apps.get_model('auth', 'Group')
    Group.objects.filter(name='cortex-qa').delete()


class Migration(migrations.Migration):

    dependencies = [
        ('identity', '0025_userprofile_access_revoked_before'),
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.RunPython(create_cortex_qa_group, remove_cortex_qa_group),
    ]
