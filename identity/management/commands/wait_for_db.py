import logging
import time

from django.core.management.base import BaseCommand
from django.db import connections
from django.db.utils import OperationalError

logger = logging.getLogger(__name__)

# PLS-79: On DNS blip at startup, retry before giving up. Auth failures still
# fail fast so a misconfigured credential doesn't silently spin for 4 minutes.
_RETRY_DELAYS = [5, 15, 30, 60, 120]


def _classify_error(exc: Exception) -> str:
    msg = str(exc).lower()
    if any(k in msg for k in ("password", "authentication failed", "role", "peer authentication")):
        return "auth"
    if any(k in msg for k in (
        "name or service not known",
        "nodename nor servname provided",
        "getaddrinfo",
        "temporary failure in name resolution",
        "name resolution failed",
    )):
        return "dns"
    if any(k in msg for k in ("connection refused", "connect failed", "timed out", "timeout")):
        return "connection"
    return "unknown"


class Command(BaseCommand):
    help = "Wait for the database to become reachable, with retry/backoff (PLS-79)."

    def handle(self, *args, **options):
        max_attempts = len(_RETRY_DELAYS) + 1
        for attempt in range(1, max_attempts + 1):
            try:
                conn = connections["default"]
                conn.ensure_connection()
                self.stdout.write(
                    self.style.SUCCESS(
                        f"Database is ready (attempt {attempt}/{max_attempts})."
                    )
                )
                return
            except (OperationalError, Exception) as exc:
                reason = _classify_error(exc)
                if reason == "auth":
                    self.stderr.write(
                        self.style.ERROR(
                            f"Database auth failure — misconfigured credentials, not retrying: {exc}"
                        )
                    )
                    raise SystemExit(1)

                delay = _RETRY_DELAYS[attempt - 1] if attempt <= len(_RETRY_DELAYS) else None
                self.stdout.write(
                    f"DB not ready (attempt {attempt}/{max_attempts}, reason={reason}): {exc}"
                )
                if delay is not None:
                    self.stdout.write(f"Retrying DB connection in {delay}s...")
                    time.sleep(delay)
                else:
                    self.stderr.write(
                        self.style.ERROR(
                            "Exhausted all DB connection retries — giving up."
                        )
                    )
                    raise SystemExit(1)
