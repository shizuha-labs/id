from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from identity.credential_keys import DEFAULT_CREDENTIAL_KEY_PATH, CredentialKeyError, provision_credential_key


class Command(BaseCommand):
    help = "Provision the AgentCredential payload MultiFernet key file without printing key material."

    def add_arguments(self, parser):
        parser.add_argument(
            "--path",
            default=str(DEFAULT_CREDENTIAL_KEY_PATH),
            help="Credential key path to create/tighten (default: /etc/shizuha/credential.key).",
        )
        parser.add_argument("--owner-uid", type=int, default=None, help="Optional daemon user uid to chown the file to.")
        parser.add_argument("--owner-gid", type=int, default=None, help="Optional daemon group gid to chown the file to.")

    def handle(self, *args, **options):
        try:
            result = provision_credential_key(
                options["path"],
                owner_uid=options.get("owner_uid"),
                owner_gid=options.get("owner_gid"),
            )
        except (CredentialKeyError, OSError) as exc:
            raise CommandError(str(exc)) from exc

        state = "created" if result.created else "exists"
        self.stdout.write(
            self.style.SUCCESS(
                f"credential key {state}: path={result.path} mode={oct(result.mode)} uid={result.uid} gid={result.gid}"
            )
        )
