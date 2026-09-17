#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise production logout evidence readers without changing a session."""

import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(sys.argv.pop(1)).read_text()
AUDIT = re.search(r"audit_shell_abends\(\) \{\n.*?\n\}", SOURCE, re.S).group(0)
JOURNAL = re.search(r"if ! python3 [^\n]* <<'PY'\n(.*?)\nPY", SOURCE, re.S).group(1)
SHUTDOWN = {"_EXE": "/usr/bin/gnome-shell", "_PID": "4242", "_UID": "1000",
            "MESSAGE": "Shutting down GNOME Shell"}
ABEND = ('type=ANOM_ABEND msg=audit(1.001:1): pid=4242 '
         'exe="/usr/bin/gnome-shell" sig=11\n')


class LogoutEvidenceTests(unittest.TestCase):
    def audit(self, stdout="", stderr="", rc=0):
        with tempfile.TemporaryDirectory(prefix="noid-logout-evidence-", dir="/var/tmp") as td:
            root = Path(td)
            (root / "stdout").write_text(stdout)
            (root / "stderr").write_text(stderr)
            # Replace only the native command transport; the tested reader,
            # diagnostic handling and counting are extracted from production.
            code = ("set -euo pipefail\nfail() { echo \"$*\" >&2; exit 1; }\n"
                'ausearch() { cat -- "$FIXTURE_ROOT/stdout"; '
                'cat -- "$FIXTURE_ROOT/stderr" >&2; return "$FIXTURE_RC"; }\n'
                + AUDIT + "\naudit_shell_abends\n")
            return subprocess.run(["bash", "-c", code], capture_output=True, text=True,
                                  env={"PATH": "/usr/bin:/bin", "LC_ALL": "C",
                                       "FIXTURE_ROOT": str(root), "FIXTURE_RC": str(rc)},
                                  timeout=5)

    def journal(self, rows):
        with tempfile.TemporaryDirectory(prefix="noid-logout-journal-", dir="/var/tmp") as td:
            path = Path(td) / "journal.json"
            path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
            return subprocess.run([sys.executable, "-", str(path), "4242", "1000"],
                                  input=JOURNAL, capture_output=True, text=True, timeout=5)

    def test_native_empty_no_match_status_is_zero_anomalies(self):
        result = self.audit(rc=1)
        self.assertEqual((result.returncode, result.stdout), (0, "0\n"))

    def test_successful_native_anomaly_is_counted(self):
        result = self.audit(ABEND)
        self.assertEqual((result.returncode, result.stdout), (0, "1\n"))

    def test_input_error_is_not_no_matches(self):
        self.assertNotEqual(self.audit(stderr="Error opening input\n", rc=1).returncode, 0)

    def test_partial_and_diagnostic_results_are_rejected(self):
        for output, error, rc in [(ABEND, "", 1), (ABEND, "config error\n", 0), ("", "", 2)]:
            with self.subTest(rc=rc, error=error):
                self.assertNotEqual(self.audit(output, error, rc).returncode, 0)

    def test_unrelated_record_and_executable_field_are_not_shell_anomalies(self):
        for row in [ABEND.replace("type=ANOM_ABEND", "type=SYSCALL"),
                    ABEND.replace("exe=", "oldexe=")]:
            with self.subTest(row=row):
                self.assertEqual(self.audit(row).stdout, "0\n")

    def test_exact_prepared_shell_shutdown_passes(self):
        self.assertEqual(self.journal([SHUTDOWN]).returncode, 0)

    def test_foreign_shell_pid_or_uid_cannot_supply_shutdown(self):
        for change in [{"_PID": "9999"}, {"_UID": "1001"}, {"_PID": ["4242", "9999"]}]:
            with self.subTest(change=change):
                self.assertNotEqual(self.journal([SHUTDOWN | change]).returncode, 0)

    def test_missing_identity_or_prefixed_message_cannot_supply_shutdown(self):
        for key in ["_PID", "_UID"]:
            row = {k: v for k, v in SHUTDOWN.items() if k != key}
            self.assertNotEqual(self.journal([row]).returncode, 0)
        row = SHUTDOWN | {"MESSAGE": "unrelated: Shutting down GNOME Shell"}
        self.assertNotEqual(self.journal([row]).returncode, 0)

    def test_crash_still_fails_even_with_normal_shutdown_message(self):
        crash = SHUTDOWN | {"MESSAGE": "segfault signal 11"}
        self.assertNotEqual(self.journal([SHUTDOWN, crash]).returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
