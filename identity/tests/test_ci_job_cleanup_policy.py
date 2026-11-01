import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class CiJobCleanupPolicyTests(unittest.TestCase):
    def test_local_gate_mounts_current_workflows(self):
        gate = (ROOT / ".ci-local-gate.sh").read_text()
        self.assertIn('-v "$PWD/.forgejo":/app/.forgejo:ro', gate)
        self.assertIn("identity.tests.test_ci_job_cleanup_policy", gate)

    def test_active_workflow_jobs_expire_and_builds_clean_up(self):
        for name in ("deploy.yml", "deploy-frontend.yml"):
            with self.subTest(workflow=name):
                workflow = (ROOT / ".forgejo/workflows" / name).read_text()
                ttls = [
                    int(value)
                    for value in re.findall(
                        r"ttlSecondsAfterFinished:\s*(\d+)", workflow
                    )
                ]
                self.assertEqual(workflow.count("kind: Job"), len(ttls))
                self.assertTrue(ttls)
                self.assertTrue(all(ttl <= 300 for ttl in ttls))
                self.assertEqual(
                    workflow.count("- --cleanup"),
                    workflow.count(
                        "image: gcr.io/kaniko-project/executor:v1.23.2"
                    ),
                )
                # The shared guard captures every selected arch's terminal
                # receipt before its Job TTL can expire (build_arches.py picks
                # the arch set). Re-reading completed Jobs afterwards
                # manufactures NotFound failures, so neither workflow does.
                self.assertIn('python3 "$BUILD_GUARD" wait-jobs --namespace build "${BUILD_WAIT_JOBS[@]}"', workflow)
                self.assertIn('BUILD_WAIT_JOBS+=(--job "${ARCH}=$(job_name_for_arch "$ARCH")")', workflow)
                self.assertNotIn("wait-pair", workflow)
                self.assertNotIn("wait_job", workflow)
                self.assertNotRegex(
                    workflow, r"(?m)^\s*wait_job (?:amd64|arm64)$"
                )


if __name__ == "__main__":
    unittest.main()
