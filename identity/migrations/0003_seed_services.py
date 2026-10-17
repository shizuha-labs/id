"""
Seed all platform services into the Tool model.
"""
from django.db import migrations


SERVICES = [
    {'slug': 'admin', 'display_name': 'Admin', 'description': 'Organization administration and settings', 'icon': 'shield', 'is_default_enabled': True, 'requires_approval': False},
    {'slug': 'id', 'display_name': 'Account', 'description': 'Identity and account management', 'icon': 'user', 'is_default_enabled': True, 'requires_approval': False},
    {'slug': 'pulse', 'display_name': 'Pulse', 'description': 'Task and project management', 'icon': 'check-square', 'is_default_enabled': True, 'requires_approval': False},
    {'slug': 'notes', 'display_name': 'Notes', 'description': 'Personal notes with rich text editor', 'icon': 'file-text', 'is_default_enabled': True, 'requires_approval': False},
    {'slug': 'mail', 'display_name': 'Mail', 'description': 'Email client', 'icon': 'mail', 'is_default_enabled': True, 'requires_approval': False},
    {'slug': 'time', 'display_name': 'Time', 'description': 'Time tracking and timesheets', 'icon': 'clock', 'is_default_enabled': True, 'requires_approval': False},
    {'slug': 'connect', 'display_name': 'Connect', 'description': 'Social networking', 'icon': 'users', 'is_default_enabled': True, 'requires_approval': False},
    {'slug': 'wiki', 'display_name': 'Wiki', 'description': 'Team documentation', 'icon': 'book-open', 'is_default_enabled': True, 'requires_approval': False},
    {'slug': 'finance', 'display_name': 'Finance', 'description': 'Personal finance and expense splitting', 'icon': 'dollar-sign', 'is_default_enabled': True, 'requires_approval': False},
    {'slug': 'books', 'display_name': 'Books', 'description': 'Accounting and bookkeeping', 'icon': 'book', 'is_default_enabled': True, 'requires_approval': False},
    {'slug': 'inventory', 'display_name': 'Inventory', 'description': 'Inventory management', 'icon': 'package', 'is_default_enabled': True, 'requires_approval': False},
    {'slug': 'hr', 'display_name': 'HR', 'description': 'Human resources management', 'icon': 'briefcase', 'is_default_enabled': True, 'requires_approval': False},
    {'slug': 'drive', 'display_name': 'Drive', 'description': 'Cloud file storage', 'icon': 'hard-drive', 'is_default_enabled': False, 'requires_approval': True},
    {'slug': 'scs', 'display_name': 'Cloud', 'description': 'Cloud infrastructure management', 'icon': 'cloud', 'is_default_enabled': False, 'requires_approval': True},
    {'slug': 'agent', 'display_name': 'Agent', 'description': 'AI employee service', 'icon': 'cpu', 'is_default_enabled': False, 'requires_approval': True},
    {'slug': 'home', 'display_name': 'Home', 'description': 'Landing page and dashboard', 'icon': 'home', 'is_default_enabled': True, 'requires_approval': False},
]


def seed_services(apps, schema_editor):
    Tool = apps.get_model('identity', 'Tool')
    for svc in SERVICES:
        Tool.objects.update_or_create(
            slug=svc['slug'],
            defaults={
                'display_name': svc['display_name'],
                'description': svc['description'],
                'icon': svc['icon'],
                'minimum_tier': 'free',
                'is_active': True,
                'is_default_enabled': svc['is_default_enabled'],
                'requires_approval': svc['requires_approval'],
                'requires_superuser': False,
            }
        )


def unseed_services(apps, schema_editor):
    Tool = apps.get_model('identity', 'Tool')
    slugs = [s['slug'] for s in SERVICES]
    Tool.objects.filter(slug__in=slugs).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('identity', '0002_passwordresettoken'),
    ]

    operations = [
        migrations.RunPython(seed_services, unseed_services),
    ]
