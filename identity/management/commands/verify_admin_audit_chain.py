"""
Management command: verify_admin_audit_chain

Walk the append-only ``AdminAuditEvent`` hash chain (ID-34, HLD ID-5 §4.5) and
report its integrity: whether the chain is intact, how many events were
checked, and — if broken — the ``seq`` of the first inconsistent event and why.
Also prints per-action summary counts and a verification timestamp.

Usage:
    python manage.py verify_admin_audit_chain
    python manage.py verify_admin_audit_chain --json

Exit code is 0 when the chain verifies and 1 when tampering/gaps are detected,
so it can gate an ops/cron integrity check.

Read-only: never mutates the ledger. Output is safe (counts, actions, hashes,
seq numbers) — no before/after payloads are printed.
"""
import json

from django.core.management.base import BaseCommand
from django.db.models import Count
from django.utils import timezone

from identity.admin_audit import verify_chain
from identity.models import AdminAuditEvent


class Command(BaseCommand):
    help = 'Verify the admin-audit hash chain and report the first broken event.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--json', action='store_true', dest='as_json',
            help='Emit a single JSON object instead of human-readable lines.',
        )

    def handle(self, *args, **options):
        result = verify_chain()
        counts = {
            row['action']: row['n']
            for row in AdminAuditEvent.objects.values('action')
            .annotate(n=Count('id')).order_by('action')
        }
        verified_at = timezone.now().isoformat()

        payload = {
            'ok': result.ok,
            'checked': result.checked,
            'first_bad_seq': result.first_bad_seq,
            'reason': result.reason,
            'action_counts': counts,
            'verified_at': verified_at,
        }

        if options['as_json']:
            self.stdout.write(json.dumps(payload, sort_keys=True))
        else:
            status = 'OK' if result.ok else 'BROKEN'
            self.stdout.write(f'admin-audit chain: {status}')
            self.stdout.write(f'  events checked: {result.checked}')
            if not result.ok:
                self.stdout.write(f'  first bad seq:  {result.first_bad_seq}')
                self.stdout.write(f'  reason:         {result.reason}')
            self.stdout.write('  action counts:')
            for action, n in sorted(counts.items()):
                self.stdout.write(f'    {action}: {n}')
            self.stdout.write(f'  verified at:    {verified_at}')

        if not result.ok:
            # Non-zero exit so cron/CI integrity checks fail loudly.
            raise SystemExit(1)
