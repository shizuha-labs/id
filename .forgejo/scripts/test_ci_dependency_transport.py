from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[2]
DEPLOY = ROOT / ".forgejo/workflows/deploy.yml"
FRONTEND = ROOT / ".forgejo/workflows/deploy-frontend.yml"
PREMERGE = ROOT / ".forgejo/workflows/premerge.yml"
POLICY = (
    "export DEBIAN_FRONTEND=noninteractive PIP_DEFAULT_TIMEOUT=120 "
    "PIP_RETRIES=5 UV_HTTP_TIMEOUT=120 UV_HTTP_RETRIES=5"
)
COMMANDS = (
    "retry python -m pip install --index-url "
    "http://pip-cache.registry.svc.cluster.local/simple --trusted-host "
    "pip-cache.registry.svc.cluster.local --upgrade pip",
    "retry python -m pip install --index-url "
    "http://pip-cache.registry.svc.cluster.local/simple --trusted-host "
    "pip-cache.registry.svc.cluster.local uv==0.11.26",
    "retry uv sync --frozen --extra dev --no-install-project --no-editable "
    "--index-url http://pip-cache.registry.svc.cluster.local/simple "
    "--allow-insecure-host pip-cache.registry.svc.cluster.local",
)


class CiDependencyTransportTests(unittest.TestCase):
    def test_id70_session_logout_regressions_gate_premerge_and_deploy(self) -> None:
        # ID-68 consolidated every identity test (incl. the ID-70 logout
        # revocation regressions) behind the exact-failure-ratchet gate.
        # Both workflows must run that gate so the regressions stay enforced.
        required = ("ci/run_identity_test_gate.py",)
        for workflow in (PREMERGE, DEPLOY):
            with self.subTest(workflow=workflow.name):
                text = workflow.read_text()
                for module in required:
                    self.assertIn(module, text)

    def test_production_gate_uses_the_exact_built_image_without_dependency_transport(self) -> None:
        deploy = DEPLOY.read_text()
        gate = deploy[deploy.index("  migration-gate:") : deploy.index("  build:")]

        self.assertIn("    needs: build\n    runs-on: deploy-lane", gate)
        self.assertIn(
            "image: localhost:30500/shizuha-id:${TAG}", gate
        )
        self.assertIn("imagePullPolicy: Always", gate)
        self.assertEqual(gate.count("restartPolicy: Always"), 2)
        self.assertIn("image: localhost:30500/hive-ci-postgres:16-alpine", gate)
        self.assertIn("image: localhost:30500/hive-ci-redis:7-alpine", gate)
        self.assertNotIn("image: postgres:15", gate)
        self.assertNotIn("image: redis:7-alpine", gate)
        self.assertIn('export PATH="/app/.venv/bin:\\$PATH"', gate)
        self.assertIn("activeDeadlineSeconds: 1200", gate)
        self.assertIn(
            "kubectl delete job -n build -l app=ci-migration-gate,service=id", gate
        )
        self.assertNotIn("git-clone", gate)
        self.assertNotIn("uv sync", gate)
        self.assertNotIn("apt-get", gate)

    def test_premerge_dependency_downloads_have_bounded_retries_and_timeouts(self) -> None:
        text = PREMERGE.read_text()
        self.assertIn(POLICY, text)
        self.assertEqual(text.count("                        retry() {"), 1)
        self.assertIn('while ! "\\$@"; do', text)
        self.assertIn('if [ "\\$attempt" -ge 3 ]; then', text)
        self.assertIn('sleep \\$((attempt * 10))', text)
        for command in COMMANDS:
            self.assertIn(command, text)

    def test_backend_build_jobs_are_bounded_and_reap_superseded_runs(self) -> None:
        deploy = DEPLOY.read_text()
        backend_job_pattern = (
            r"^job\.batch/(ci-build-id-[0-9a-f]{7}-(amd64|arm64)|"
            r"ci-manifest-id-[0-9a-f]{7}|ci-verify-shizuha-id-[0-9a-f]{7})$"
        )
        self.assertIn(f"'{backend_job_pattern}'", deploy)
        for frontend_job in (
            "job.batch/ci-build-id-frontend-deadbee-amd64",
            "job.batch/ci-manifest-id-frontend-deadbee",
            "job.batch/ci-verify-shizuha-id-frontend-deadbee",
        ):
            with self.subTest(frontend_job=frontend_job):
                self.assertIsNone(re.fullmatch(backend_job_pattern, frontend_job))
        self.assertIn('kubectl delete -n build "${STALE_ID_JOBS[@]}"', deploy)
        self.assertEqual(deploy.count("activeDeadlineSeconds:"), 4)
        self.assertIn("activeDeadlineSeconds: 1800", deploy)
        self.assertIn("activeDeadlineSeconds: 300", deploy)
        self.assertIn("activeDeadlineSeconds: 180", deploy)
        self.assertIn("  deploy:\n    needs: [migration-gate]", deploy)

    def test_frontend_build_jobs_are_bounded_and_reap_superseded_runs(self) -> None:
        frontend = FRONTEND.read_text()
        self.assertIn(
            "'^job.batch/(ci-build-id-frontend-|ci-manifest-id-frontend-|"
            "ci-verify-shizuha-id-frontend-)'",
            frontend,
        )
        self.assertIn(
            'kubectl delete -n build "${STALE_ID_FRONTEND_JOBS[@]}"', frontend
        )
        self.assertEqual(frontend.count("activeDeadlineSeconds:"), 3)
        self.assertIn("activeDeadlineSeconds: 1800", frontend)
        self.assertIn("activeDeadlineSeconds: 300", frontend)
        self.assertIn("activeDeadlineSeconds: 180", frontend)

    def test_build_jobs_fit_the_reserved_amd64_node(self) -> None:
        deploy = DEPLOY.read_text()
        build = deploy[deploy.index("  build:"):]
        self.assertGreaterEqual(build.count("requests: { cpu: 25m"), 2)
        self.assertIn("limits: { cpu: 2, memory: 8Gi }", build)

    def test_build_checkouts_fetch_only_the_exact_triggering_ref(self) -> None:
        for workflow in (DEPLOY, FRONTEND, PREMERGE):
            with self.subTest(workflow=workflow.name):
                text = workflow.read_text()
                self.assertNotIn("git clone --depth=50", text)
                self.assertIn('git fetch --depth=1 origin "${{ github.ref }}"', text)
                self.assertIn(
                    'test "\\$(git rev-parse HEAD)" = "${{ github.sha }}"', text,
                )

    def test_deploy_uses_reviewed_toolbox_and_verifies_embedded_clients(self) -> None:
        deploy = DEPLOY.read_text()
        rollout = deploy[deploy.index("  deploy:"):]
        self.assertIn(
            "image: registry.registry.svc.cluster.local:5000/origin-ci-helm@sha256:"
            "90f02d48d68c0ed690f9ddd8bcef1167490610362c19d429943931433ed7b194",
            rollout,
        )
        self.assertIn('kubectl version --client -o json', rollout)
        self.assertIn('== "v1.34.6"', rollout)
        self.assertIn("helm version --short | grep -F 'v3.21.2'", rollout)
        self.assertNotIn("api/packages/actions/generic/kubectl/", rollout)
        self.assertNotIn("KUBECTL_SHA256=", rollout)


if __name__ == "__main__":
    unittest.main()
