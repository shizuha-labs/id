import json

from django.core.management.base import BaseCommand, CommandError

from identity.oauth_rs256_invariant import run_oauth_rs256_invariant_probe


class Command(BaseCommand):
    help = 'Fail unless all ID OAuth grants mint RS256 tokens with a kid header.'

    def handle(self, *args, **options):
        try:
            result = run_oauth_rs256_invariant_probe()
        except Exception as exc:
            raise CommandError(f'ID OAuth RS256 invariant failed: {exc}') from exc
        self.stdout.write(self.style.SUCCESS(
            'ID OAuth RS256 invariant PASS ' + json.dumps(result, sort_keys=True)
        ))
