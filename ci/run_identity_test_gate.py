#!/usr/bin/env python3
"""Run every identity test with an exact known-failure ratchet."""
from __future__ import annotations

import argparse
import json
import os
import sys
import unittest
from pathlib import Path

import django
from django.test.runner import DiscoverRunner, iter_test_cases

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
DEFAULT_BASELINE = ROOT / "ci/identity_test_baseline.json"
TEST_PREFIX = "identity.tests."
FAILED_TEST_PREFIX = "unittest.loader._FailedTest."


def load_baseline(path: Path) -> set[str]:
    raw = json.loads(path.read_text())
    if not isinstance(raw, list):
        raise ValueError("baseline must be a JSON array")
    for test_id in raw:
        if not isinstance(test_id, str) or not test_id.startswith(TEST_PREFIX):
            raise ValueError(f"invalid baseline test ID: {test_id!r}")
    if len(raw) != len(set(raw)):
        raise ValueError("baseline contains duplicate test IDs")
    return set(raw)


def logical_test_id(test: unittest.case.TestCase) -> str:
    test_id = test.id()
    if test_id.startswith(FAILED_TEST_PREFIX):
        return test_id.removeprefix(FAILED_TEST_PREFIX)
    return test_id


def failure_ids(result: unittest.TestResult) -> set[str]:
    return {
        logical_test_id(test)
        for test, _traceback in (*result.failures, *result.errors)
    }


class RatchetDiscoverRunner(DiscoverRunner):
    baseline_path = DEFAULT_BASELINE

    def suite_result(self, suite, result, **kwargs):
        baseline = load_baseline(Path(self.baseline_path))
        actual = failure_ids(result)
        new_failures = actual - baseline
        newly_passing = baseline - actual
        if new_failures or newly_passing:
            self.log("Identity test baseline drift:")
            for test_id in sorted(new_failures):
                self.log(f"  NEW FAILURE: {test_id}")
            for test_id in sorted(newly_passing):
                self.log(f"  NOW PASSING; remove from baseline: {test_id}")
            return 1
        self.log(
            f"Identity test baseline matched: {len(actual)} exact known failures; "
            "all other discovered tests passed."
        )
        return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--verbosity", type=int, default=1)
    parser.add_argument("test_labels", nargs="*", default=["identity"])
    args = parser.parse_args()

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "shizuha_id.settings")
    django.setup()
    runner = RatchetDiscoverRunner(verbosity=args.verbosity, interactive=False)
    runner.baseline_path = args.baseline
    return runner.run_tests(args.test_labels)


if __name__ == "__main__":
    sys.exit(main())
