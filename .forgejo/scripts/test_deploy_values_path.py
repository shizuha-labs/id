from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("deploy-values-path.py")
ROOT = SCRIPT.parents[2]
SPEC = importlib.util.spec_from_file_location("deploy_values_path", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DeployValuesPathTests(unittest.TestCase):
    def test_lifecycle_is_the_only_id_release_writer(self) -> None:
        backend = (ROOT / ".forgejo/workflows/deploy.yml").read_text()
        frontend = (ROOT / ".forgejo/workflows/deploy-frontend.yml").read_text()
        self.assertIn("runs-on: deploy-lane", frontend)
        self.assertIn('deploy-values-path.py set /tmp/id-values.yaml image.tag "${TAG}"', backend)
        self.assertIn('deploy-values-path.py set /tmp/id-values.yaml frontend.image.tag "${FTAG}"', frontend)
        self.assertIn('desired backend tag ${TAG} before rollout', backend)
        self.assertIn('desired frontend tag ${FTAG} before rollout', frontend)
        self.assertIn('deploy values changed concurrently; retrying fresh read', backend)
        self.assertIn('deploy values changed concurrently; retrying fresh read', frontend)
        self.assertIn('central lifecycle did not converge ID release', backend)
        self.assertIn('central lifecycle did not converge ID frontend', frontend)
        self.assertIn('HELM_VERSION=v3.16.4', frontend)
        self.assertIn('helm version --short', frontend)
        self.assertIn("for attempt in $(seq 1 540)", backend)
        self.assertIn("for attempt in $(seq 1 540)", frontend)
        self.assertIn('status.get("updatedReplicas", 0) == replicas', backend)
        self.assertIn('status.get("availableReplicas", 0) == replicas', frontend)
        self.assertIn("deployment_converged shizuha-id-lifecycle-relay", backend)
        self.assertIn("deployment_converged shizuha-id-frontend", backend)
        self.assertIn('STORED_FRONTEND_TAG="$(helm get values shizuha-id', backend)
        self.assertIn('FINAL_FRONTEND_TAG="$(python3 .forgejo/scripts/deploy-values-path.py get', frontend)
        self.assertNotIn("helm upgrade shizuha-id", backend)
        self.assertNotIn("kubectl set image", frontend)
        self.assertNotIn("[ci skip]", backend)

    def test_existing_desired_tag_redispatches_reconciliation(self) -> None:
        backend = (ROOT / ".forgejo/workflows/deploy.yml").read_text()
        frontend = (ROOT / ".forgejo/workflows/deploy-frontend.yml").read_text()
        dispatch_path = "actions/workflows/deploy-id-mail-lifecycle.yml/dispatches"
        self.assertIn("PROMOTED=false", backend)
        self.assertIn("PROMOTED=true", backend)
        self.assertIn(dispatch_path, backend)
        self.assertIn("PROMOTED=false", frontend)
        self.assertIn("PROMOTED=true", frontend)
        self.assertIn(dispatch_path, frontend)

    def test_updates_only_the_requested_nested_tag(self) -> None:
        source = (
            "image:\n"
            "  tag: id-old\n"
            "frontend:\n"
            "  image:\n"
            "    repository: localhost:30500/shizuha-id-frontend\n"
            "    tag: id-frontend-old\n"
            "relay:\n"
            "  image:\n"
            "    tag: relay-old\n"
        )
        lines = source.splitlines(keepends=True)
        index, match, old = MODULE.find_scalar(lines, ("frontend", "image", "tag"))
        self.assertEqual(old, "id-frontend-old")
        lines[index] = (
            f'{match.group("prefix")}{match.group("key")}:'
            f'{match.group("separator")}id-frontend-new{match.group("newline")}'
        )
        updated = "".join(lines)
        self.assertIn("  tag: id-old\n", updated)
        self.assertIn("    tag: id-frontend-new\n", updated)
        self.assertIn("    tag: relay-old\n", updated)

    def test_missing_path_fails_closed(self) -> None:
        with self.assertRaisesRegex(SystemExit, "could not locate frontend.image.tag"):
            MODULE.find_scalar(["image:\n", "  tag: id-old\n"], ("frontend", "image", "tag"))

    def test_cli_preserves_file_shape(self) -> None:
        source = "frontend:\n  image:\n    tag: old\n\nother: value\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "values.yaml"
            path.write_text(source)
            lines = path.read_text().splitlines(keepends=True)
            index, match, _ = MODULE.find_scalar(lines, ("frontend", "image", "tag"))
            lines[index] = (
                f'{match.group("prefix")}{match.group("key")}:'
                f'{match.group("separator")}new{match.group("newline")}'
            )
            path.write_text("".join(lines))
            self.assertEqual(path.read_text(), source.replace("    tag: old", "    tag: new"))


if __name__ == "__main__":
    unittest.main()
