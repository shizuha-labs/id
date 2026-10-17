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
                if name == "deploy.yml":
                    # The shared guard captures both terminal receipts before
                    # their Job TTL can expire. Re-reading completed Jobs
                    # afterwards manufactures NotFound failures.
                    self.assertIn('python3 "$BUILD_GUARD" wait-pair', workflow)
                    self.assertIn('--job "amd64=${AMD64_JOB}" --job "arm64=${ARM64_JOB}"', workflow)
                    self.assertNotIn("wait_job ", workflow)
                else:
                    self.assertIn("wait_job amd64 &", workflow)
                    self.assertIn("wait_job arm64 &", workflow)
                self.assertNotRegex(
                    workflow, r"(?m)^\s*wait_job (?:amd64|arm64)$"
                )


if __name__ == "__main__":
    unittest.main()
