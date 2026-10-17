"""Backfill a valid stock avatar for every user that has none.

Operator 2026-08: all users must have a valid avatar (avatar == profile image).
New signups are covered at creation time; this command sweeps pre-existing users
whose ``UserProfile.profile_picture`` is empty/null and assigns the deterministic
stock avatar for their username (identical to what Hive renders for the same
identity). Custom/chosen profile pictures are never overwritten.

Usage:
    python manage.py backfill_avatars             # backfill all, no dry-run
    python manage.py backfill_avatars --dry-run   # report only, change nothing
"""
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand

from identity.avatars import assign_default_avatar

User = get_user_model()


class Command(BaseCommand):
    help = 'Assign a stock avatar to every user with no profile picture.'

    def add_arguments(self, parser):
        parser.add_argument('--dry-run', action='store_true', help='Report without writing')

    def handle(self, *args, **options):
        dry = options['dry_run']
        # Only users with a profile row and no chosen picture.
        users = (
            User.objects.filter(profile__isnull=False)
            .exclude(profile__profile_picture__isnull=False)
            .exclude(profile__profile_picture__exact='')
            .select_related('profile')
        )
        total = users.count()
        self.stdout.write(f'found {total} user(s) without a profile picture')
        if dry:
            self.stdout.write('dry-run: no changes written')
            return

        updated = 0
        for user in users.iterator(chunk_size=500):
            url = assign_default_avatar(user.profile, user.username)
            if url:
                updated += 1
        self.stdout.write(self.style.SUCCESS(f'assigned stock avatars to {updated} user(s)'))
