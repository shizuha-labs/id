"""The complete-suite ratchet must also enforce a debt-free baseline."""
import json
import tempfile
import unittest
from pathlib import Path
from django.test import SimpleTestCase
from ci.run_identity_test_gate import RatchetDiscoverRunner, load_baseline


class IdentityFullGateContractTests(SimpleTestCase):
    def baseline(self, value):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / 'baseline.json'
        path.write_text(json.dumps(value))
        return path

    def result(self, baseline, *, failed=False, error=False):
        class Sample(unittest.TestCase):
            def runTest(self):
                pass
            def id(self):
                return 'identity.tests.sample.Sample.runTest'
        test = Sample()
        suite = unittest.TestSuite([test])
        result = unittest.TestResult()
        if failed:
            result.failures.append((test, 'assertion failure'))
        if error:
            result.errors.append((test, 'unexpected exception'))
        runner = RatchetDiscoverRunner(verbosity=0, interactive=False)
        runner.baseline_path = self.baseline(baseline)
        return runner.suite_result(suite, result)

    def test_empty_baseline_accepts_complete_success(self):
        self.assertEqual(load_baseline(self.baseline([])), set())
        self.assertEqual(self.result([]), 0)

    def test_empty_baseline_refuses_failure_and_error(self):
        self.assertEqual(self.result([], failed=True), 1)
        self.assertEqual(self.result([], error=True), 1)

    def test_known_failure_cannot_hide_new_failure_or_new_pass(self):
        known = ['identity.tests.sample.Sample.runTest']
        self.assertEqual(self.result(known, failed=True), 0)
        self.assertEqual(self.result(known), 1)
        self.assertEqual(self.result(['identity.tests.other.Sample.runTest'], failed=True), 1)

    def test_malformed_baselines_fail_closed(self):
        for value in ({}, None, '', [None], [{}], ['other.test'],
                      ['identity.tests.a', 'identity.tests.a']):
            with self.subTest(value=value), self.assertRaises(ValueError):
                load_baseline(self.baseline(value))
