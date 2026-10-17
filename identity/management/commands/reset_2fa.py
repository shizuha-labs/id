"""Host-side 2FA break-glass reset (PLAT-493 / SEC-2)."""
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from identity.models import RecoveryCode, TOTPDevice, UserProfile


class Command(BaseCommand):
    help = 'Reset login/step-up 2FA factors and recovery codes for a user so they can re-enroll.'

    def add_arguments(self, parser):
        parser.add_argument('user', help='Username, email, or numeric user id')
        parser.add_argument('--reason', required=True, help='Audit reason for break-glass reset')
        parser.add_argument('--confirm', action='store_true', help='Required safety flag')

    def handle(self, *args, **options):
        if not options['confirm']:
            raise CommandError('Refusing reset without --confirm')
        User = get_user_model()
        ident = options['user']
        qs = User.objects.all()
        if ident.isdigit():
            user = qs.filter(pk=int(ident)).first()
        else:
            user = qs.filter(username__iexact=ident).first() or qs.filter(email__iexact=ident).first()
        if not user:
            raise CommandError('User not found')

        now = timezone.now()
        device_count = TOTPDevice.objects.filter(user=user, confirmed=True).update(confirmed=False)
        RecoveryCode.objects.filter(user=user, used_at__isnull=True).update(used_at=now)
        profile, _ = UserProfile.objects.get_or_create(user=user)
        profile.twofa_enrolled_at = None
        profile.twofa_enforced = False
        profile.twofa_enforcement_deadline = None
        profile.save(update_fields=['twofa_enrolled_at', 'twofa_enforced', 'twofa_enforcement_deadline', 'updated_at'])
        self.stdout.write(
            self.style.SUCCESS(
                f'Reset 2FA for user_id={user.pk}; disabled_devices={device_count}; reason={options["reason"]}'
            )
        )
