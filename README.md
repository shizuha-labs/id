# Shizuha ID

Identity, sign-in, organization membership and OAuth for the Shizuha platform.

## Deploy the platform

Use the [platform deployment repository](https://github.com/shizuha-labs/deploy)
for the coordinated installation of ID, Hive, Pulse, Connect, Wiki and Atlas.
Service repositories provide application source; deployment configuration owns
hostnames, credentials, storage and inter-service trust.

Django API and React frontend; PostgreSQL and Redis.

Configuration is read by [`shizuha_id/settings.py`](shizuha_id/settings.py). Supply deployment-specific
credentials and endpoints through the environment. Existing production-cluster
manifests and internal CI workflows are not an external installation recipe.

## Development

Backend dependencies are declared in `pyproject.toml` and `uv.lock`;
frontend dependencies are in `frontend/package.json` and its lockfile.
The repository's `.forgejo/workflows/premerge.yml` documents its test recipe.
Run tests against isolated databases and service dependencies.

## License

Original code is available under the [MIT License](LICENSE). Third-party
components retain their respective licenses and notices. Dependency licenses
are not replaced by this repository's license.

Demo seeding is disabled unless `SHIZUHA_DEMO_PASSWORD` is provided through a
deployment secret. Optional `SHIZUHA_DEMO_USERNAME` and `SHIZUHA_DEMO_EMAIL`
select the demo identity. Existing accounts remain unchanged on startup;
`manage.py seed_demo_user --reset-password` explicitly resets its password.

### Installation credentials

Set `POSTGRES_PASSWORD` and an explicit signing key before running Django.
`JWT_SECRET_KEY` keeps its existing precedence when present; otherwise supply
`SECRET_KEY`. Missing or blank selected keys/passwords refuse startup, including
with `DEBUG=False`. Explicit blank `JWT_SECRET_KEY` does not fall back to another
key. Configured bytes are preserved, so this change does not rotate keys.
Build-only static collection and disposable tests must supply their own explicit
fixtures; those fixtures are not runtime defaults.
