"""Opt-in demo account provisioning with deployment-supplied credentials."""
import os

from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

from identity.models import UserProfile

User = get_user_model()


class Command(BaseCommand):
    help = 'Create an opt-in demo user; existing accounts stay unchanged by default'

    def add_arguments(self, parser):
        parser.add_argument('--reset-password', action='store_true',
                            help='Explicitly replace an existing demo account password')

    def handle(self, *args, **options):
        password = os.environ.get('SHIZUHA_DEMO_PASSWORD', '')
        if not password.strip():
            self.stdout.write('Demo seed disabled: SHIZUHA_DEMO_PASSWORD is not configured')
            return
        username = os.environ.get('SHIZUHA_DEMO_USERNAME', 'demo').strip() or 'demo'
        email = os.environ.get('SHIZUHA_DEMO_EMAIL', 'demo@example.test').strip()
        user, created = User.objects.get_or_create(
            username=username,
            defaults={
                'email': email, 'first_name': 'Demo', 'last_name': 'User',
                'is_staff': False, 'is_superuser': False, 'is_active': True,
            },
        )
        if not created and not options['reset_password']:
            self.stdout.write('Demo account already exists; credentials and access unchanged')
            return
        user.set_password(password)
        user.save(update_fields=['password'])
        if created:
            profile, _ = UserProfile.objects.get_or_create(user=user)
            profile.approval_status = 'approved'
            profile.lifecycle_state = 'active'
            profile.save(update_fields=['approval_status', 'lifecycle_state'])
        self.stdout.write(self.style.SUCCESS('Demo account created' if created else 'Demo password reset'))
