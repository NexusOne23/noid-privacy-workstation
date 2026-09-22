#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the real suite runner with synthetic tests and native log failures."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SOURCE = Path(sys.argv.pop(1)).resolve()


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="noid-runner-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.tests = self.root / "tests"
        self.tests.mkdir()
        # run-all checks library presence; the synthetic scripts need no API.
        (self.tests / "lib.sh").write_text("# Synthetic test library.\n")
        self.runner = self.tests / "run-all.sh"
        shutil.copyfile(SOURCE, self.runner)
        self.temp = self.root / "tmp"
        self.temp.mkdir()
        self.destination = self.root / "log-destination"
        self.first = self.tests / "00-canary-first.sh"
        self.first.write_text("printf 'FIRST\\n'\nprintf 'STDERR\\n' >&2\nexit 0\n")
        (self.tests / "01-canary-second.sh").write_text("printf 'SECOND\\n'\n")

    def run_runner(self, verbose=True, setup="", temp=None):
        env = os.environ.copy()
        env.update(TMPDIR=str(temp or self.temp),
                   RUNNER_DESTINATION=str(self.destination),
                   SKIP_SMOKE_HINT="1")
        args = ["bash", "-c", setup + '\nexec bash "$@"',
                "runner-fixture", str(self.runner)]
        if verbose:
            args.append("--verbose")
        # The filter selects both canaries without running the full preflight
        # or any real repository test, even when invoked from within the suite.
        args.append("canary")
        return subprocess.run(args, cwd=self.root, env=env, text=True,
                              capture_output=True, timeout=15)

    def assert_harness_error(self, result, diagnostic):
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn(diagnostic, result.stderr)
        self.assertNotIn("All tests passed", result.stdout)
        self.assertNotIn("SECOND", result.stdout)

    def test_success_and_skip_counts_in_both_modes(self):
        for verbose in (False, True):
            for skips in (0, 2):
                with self.subTest(verbose=verbose, skips=skips):
                    self.first.write_text("printf 'FIRST\\n'\n" +
                                          "printf '  [SKIP] synthetic capability\\n'\n" * skips)
                    result = self.run_runner(verbose)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("All tests passed: 2/2", result.stdout)
                    if skips:
                        self.assertIn("Capability skips surfaced: 2 event(s) across 1 test(s).",
                                      result.stdout)
                    else:
                        self.assertNotIn("Capability skips surfaced:", result.stdout)
                    self.assertEqual(list(self.temp.iterdir()), [])

    def test_test_failure_is_preserved_in_both_modes(self):
        self.first.write_text("printf 'FIRST\\n'\nprintf 'STDERR\\n' >&2\nexit 7\n")
        for verbose in (False, True):
            with self.subTest(verbose=verbose):
                result = self.run_runner(verbose)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("Tests FAILED: 1/2 passed, 1 failed", result.stdout)
                self.assertIn("  - 00-canary-first", result.stdout)
                self.assertIn("STDERR", result.stdout)
                self.assertNotIn("All tests passed", result.stdout)
                self.assertEqual(list(self.temp.iterdir()), [])

    def test_native_mktemp_failure_stops_before_test(self):
        result = self.run_runner(temp=self.root / "missing-directory")
        self.assert_harness_error(result, "cannot create test log")
        self.assertNotIn("FIRST", result.stdout)

    def test_native_tee_failure_overrides_success_and_failure(self):
        self.destination.mkdir()
        # Only scratch allocation is redirected. Native tee rejects the
        # directory, reproducing a log write error independently of test rc.
        setup = '''mktemp() { printf '%s\\n' "$RUNNER_DESTINATION"; }
export -f mktemp
'''
        for test_rc in (0, 7):
            with self.subTest(test_rc=test_rc):
                self.first.write_text(f"printf 'FIRST\\n'\nexit {test_rc}\n")
                result = self.run_runner(setup=setup)
                self.assert_harness_error(result, "cannot write test log")
                self.assertIn("FIRST", result.stdout)
                self.assertIn("tee:", result.stderr)

    def test_disappeared_log_is_not_zero_skips(self):
        # Native tee succeeds; remove its scratch output before the runner's
        # native grep. This isolates read failure from an earlier write error.
        setup = '''tee() {
    command tee "$@" || return
    command rm -- "${!#}"
}
export -f tee
'''
        result = self.run_runner(setup=setup)
        self.assert_harness_error(result, "cannot read test log")
        self.assertIn("FIRST", result.stdout)

    def test_native_cleanup_error_is_not_a_success(self):
        setup = '''tee() {
    command tee "$@" || return
    command rm -- "${!#}" || return
    command mkdir -- "${!#}"
}
export -f tee
'''
        result = self.run_runner(setup=setup)
        self.assert_harness_error(result, "cannot remove test log")
        self.assertIn("FIRST", result.stdout)


if __name__ == "__main__":
    unittest.main()
