#!/bin/bash
# Local mirror of ci-test-id: the SAME curated gates CI runs (id41 lifecycle,
# ID-60 authz/isolation list, ID-61 RS256 invariant) — no more, no less.
# Speed (2026-07-14): pg data persists on volume id-gate-pgdata + --keepdb, so
# the 3 invocations stop re-creating/migrating the test DB each push.
# Reset if a rebased migration wedges it: docker volume rm id-gate-pgdata
set -euo pipefail
# Concurrent gate runs share the id-gate-pgdata volume: two postgres
# containers on one data dir corrupt it (then every later run wedges in crash
# recovery). flock queues concurrent pushes; 15min cap then fail loud.
exec 9>/tmp/id-gate.volume.lock
flock -w 900 9 || { echo "gate: another gate run held the lock >15min — investigate (docker ps | grep id-gate)" >&2; exit 1; }
cd "$(git rev-parse --show-toplevel)"
echo "gate: deployment and credential-safe CI contracts"
python3 .forgejo/scripts/test_deploy_values_path.py
python3 .forgejo/scripts/test_ci_dependency_transport.py
python3 .forgejo/scripts/test_identity_test_gate.py
python3 .forgejo/tests/test_build_completion_receipt.py
echo "gate: uv lock consistency"
command -v uv >/dev/null 2>&1 || {
  echo "gate: uv is required to verify pyproject.toml against uv.lock" >&2
  exit 1
}
env -u UV_DEFAULT_INDEX -u UV_INDEX_URL -u UV_INSECURE_HOST \
  uv lock --check --no-progress
IMG="${SHIZUHA_CI_IMAGE:-}"
[ -z "$IMG" ] && command -v kubectl >/dev/null 2>&1 && IMG=$(kubectl get deploy -n shizuha shizuha-id -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null || true)
IMG="${IMG:-localhost:30500/shizuha-id:id-4a8f209}"
NET="id-gate-$$"; PG="id-gate-pg-$$"; RD="id-gate-redis-$$"
cleanup() { docker stop -t 20 "$PG" >/dev/null 2>&1 || true; docker rm -f "$PG" "$RD" >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker volume create id-gate-pgdata >/dev/null
docker network create "$NET" >/dev/null
docker run -d --name "$PG" --network "$NET" -v id-gate-pgdata:/var/lib/postgresql/data -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=shizuha_id_ci postgres:16-alpine >/dev/null
docker run -d --name "$RD" --network "$NET" redis:7-alpine >/dev/null
wait_pg() {
  for _i in $(seq 1 90); do
    docker exec "$PG" psql -U postgres -h 127.0.0.1 -c "SELECT 1" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}
if ! wait_pg; then
  # Cached volume wedged (interrupted WAL recovery etc.) — it is only a cache:
  # recreate it fresh and retry once (next run repays migrations, then warm again).
  echo "gate: postgres not ready — recreating cache volume id-gate-pgdata and retrying" >&2
  docker rm -f "$PG" >/dev/null 2>&1
  docker volume rm id-gate-pgdata >/dev/null 2>&1
  docker volume create id-gate-pgdata >/dev/null
  docker run -d --name "$PG" --network "$NET" -v id-gate-pgdata:/var/lib/postgresql/data -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=shizuha_id_ci postgres:16-alpine >/dev/null
  wait_pg || { echo "gate: postgres STILL not ready — aborting" >&2; exit 1; }
fi
echo "gate: image=$IMG"
docker run --rm --network "$NET" \
  -v "$PWD/identity":/app/identity -v "$PWD/shizuha_id":/app/shizuha_id \
  -v "$PWD/.forgejo":/app/.forgejo:ro \
  -v "$PWD/.ci-local-gate.sh":/app/.ci-local-gate.sh:ro \
  -e POSTGRES_HOST="$PG" -e POSTGRES_PORT=5432 -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=shizuha_id_ci \
  -e DB_NAME=shizuha_id_ci -e DB_USER=postgres -e DB_PASSWORD=postgres -e DB_HOST="$PG" -e DB_PORT=5432 \
  -e REDIS_URL="redis://$RD:6379/5" -e CACHE_REDIS_URL="redis://$RD:6379/6" \
  -e DEBUG=True -e SECRET_KEY=ci-secret -e JWT_SECRET_KEY=ci-secret -e SHIZUHA_JWT_SIGNING_KEY=ci-secret \
  "$IMG" sh -c "uv pip install --quiet --python /app/.venv/bin/python --index-url http://192.168.0.136:30511/simple/ "fakeredis[lua]==2.36.2" && \
python manage.py test identity.tests.test_id41_lifecycle_token_revocation -v1 --keepdb && \
python manage.py test \
  identity.tests.test_id65_logout_blacklist \
  identity.tests.test_id13_user_access_revocation \
  identity.tests.test_id21_push_token_purge_on_revoke \
  -v1 --keepdb && \
python manage.py test \
  identity.tests.test_ci_job_cleanup_policy \
  identity.tests.test_id33_admin_permissions.AdminPermissionGateTests.test_public_staff_admin_endpoints_reject_non_admins_and_allow_staff \
  identity.tests.test_id46_directory_scope \
  identity.tests.test_id52_pii_field_scoping \
  identity.tests.test_id53_list_hardening \
  identity.tests.test_id54_enumeration_oracle \
  identity.tests.test_id58_service_token_phase_a \
  -v1 --keepdb && \
python manage.py test identity.tests.test_oauth_rs256_invariant -v1 --keepdb && \
python manage.py test identity.tests.test_mail74_token_exchange -v1 --keepdb"
