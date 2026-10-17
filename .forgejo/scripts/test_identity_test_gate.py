from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).parents[2]
MODULE_PATH = ROOT / "ci/run_identity_test_gate.py"
SPEC = importlib.util.spec_from_file_location("identity_test_gate", MODULE_PATH)
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class _Test:
    def __init__(self, test_id: str):
        self._test_id = test_id

    def id(self) -> str:
        return self._test_id


class IdentityTestGateTests(unittest.TestCase):
    def test_failure_ids_include_import_errors_and_test_failures(self) -> None:
        result = mock.Mock(
            failures=[(_Test("identity.tests.test_alpha.Case.test_one"), "trace")],
            errors=[(
                _Test("unittest.loader._FailedTest.identity.tests.test_beta"),
                "trace",
            )],
        )
        self.assertEqual(
            GATE.failure_ids(result),
            {
                "identity.tests.test_alpha.Case.test_one",
                "identity.tests.test_beta",
            },
        )

    def test_exact_baseline_passes(self) -> None:
        result = mock.Mock(
            failures=[(_Test("identity.tests.test_alpha.Case.test_one"), "trace")],
            errors=[],
        )
        self.assertEqual(
            self._suite_result(
                result,
                ["identity.tests.test_alpha.Case.test_one"],
            ),
            0,
        )

    def test_new_failure_fails(self) -> None:
        result = mock.Mock(
            failures=[(_Test("identity.tests.test_new.Case.test_one"), "trace")],
            errors=[],
        )
        self.assertEqual(
            self._suite_result(
                result,
                ["identity.tests.test_alpha.Case.test_one"],
            ),
            1,
        )

    def test_newly_passing_baseline_entry_fails_until_removed(self) -> None:
        result = mock.Mock(failures=[], errors=[])
        self.assertEqual(
            self._suite_result(
                result,
                ["identity.tests.test_alpha.Case.test_one"],
            ),
            1,
        )

    def test_failure_swap_in_same_module_fails(self) -> None:
        result = mock.Mock(
            failures=[(_Test("identity.tests.test_alpha.Case.test_new"), "trace")],
            errors=[],
        )
        self.assertEqual(
            self._suite_result(
                result,
                ["identity.tests.test_alpha.Case.test_old"],
            ),
            1,
        )

    def test_workflows_share_the_default_on_gate(self) -> None:
        command = "python ci/run_identity_test_gate.py --verbosity 1"
        workflows = [
            (ROOT / ".forgejo/workflows/premerge.yml").read_text(),
            (ROOT / ".forgejo/workflows/deploy.yml").read_text(),
        ]
        for workflow in workflows:
            self.assertEqual(workflow.count(command), 1)
            self.assertNotIn("python manage.py test identity.tests.", workflow)

    def test_throwaway_module_is_discoverable_without_workflow_edits(self) -> None:
        sentinel = ROOT / "identity/tests/test_id68_discovery_sentinel.py"
        sentinel.write_text(
            "from unittest import TestCase\n"
            "class Id68Sentinel(TestCase):\n"
            "    def test_discovered(self): pass\n"
        )
        try:
            spec = importlib.util.spec_from_file_location("id68_sentinel", sentinel)
            assert spec and spec.loader
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            suite = unittest.defaultTestLoader.loadTestsFromModule(module)
            self.assertIn(
                "id68_sentinel.Id68Sentinel.test_discovered",
                {test.id() for test in GATE.iter_test_cases(suite)},
            )
        finally:
            sys.modules.pop("id68_sentinel", None)
            sentinel.unlink(missing_ok=True)

    def _suite_result(self, result: mock.Mock, baseline: list[str]) -> int:
        with tempfile.TemporaryDirectory() as directory:
            baseline_path = Path(directory) / "baseline.json"
            baseline_path.write_text(json.dumps(baseline))
            runner = GATE.RatchetDiscoverRunner(verbosity=0)
            runner.baseline_path = baseline_path
            return runner.suite_result(None, result)


if __name__ == "__main__":
    unittest.main()
