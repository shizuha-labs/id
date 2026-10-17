"""Self-contained CI settings for the ID-41 lifecycle-revocation suite.

Mirrors the NTS-36 / PLAT-1236 pattern: sqlite + disabled migrations + local
cache so the regression suite runs in a bare runner without Postgres/Redis/JWT
infra. GitHub Actions is billing-disabled on shizuha-labs, so this is wired to a
standalone Forgejo/Origin gate that actually EXECUTES the tests on every PR/push
(see .forgejo/workflows/id41-revocation-check.yml) — the migration-gate job in
deploy.yml only checks the migration graph, it does not run the suite.
"""
import os

os.environ.setdefault('SECRET_KEY', 'id41-ci-secret')
os.environ.setdefault('JWT_SECRET_KEY', 'id41-ci-secret')
os.environ.setdefault('SHIZUHA_JWT_SIGNING_KEY', 'id41-ci-secret')

from shizuha_id.settings import *  # noqa: F401,F403,E402

# In-memory sqlite — no Postgres needed for these DB-backed lifecycle tests.
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}


class _DisableMigrations:
    def __contains__(self, item):
        return True

    def __getitem__(self, item):
        return None


MIGRATION_MODULES = _DisableMigrations()

# Local cache so prime_user_access_cutoff_cache works without Redis; the
# invariants counters are fail-open and don't require Redis in tests.
CACHES = {
    'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'},
}

PASSWORD_HASHERS = ['django.contrib.auth.hashers.MD5PasswordHasher']
