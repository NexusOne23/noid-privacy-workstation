#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check the actual candidate reader against native child-process environments."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(sys.argv.pop(1)).read_text()
START = "shell_pid=$(systemctl"
END = "\ngjs_default="
assert SOURCE.count(START) == SOURCE.count(END) == 1
BOUNDARY = START + SOURCE.split(START, 1)[1].split(END, 1)[0]
EXPECTED = {"GJS_DISABLE_JIT": "1", "JavaScriptCoreUseJIT": "0"}
BAIT = {"NOID_FIXTURE_NOTE": "ordinary text\nGJS_DISABLE_JIT=1\nJavaScriptCoreUseJIT=0"}


class JitProcessTests(unittest.TestCase):
    def run_boundary(self, process_environment, manager_rc=0, pid=None, expected_exe="/usr/bin/sleep"):
        with tempfile.TemporaryDirectory(prefix="noid-jit-process-", dir="/var/tmp") as temporary:
            root = Path(temporary)
            # The harmless native child replaces GNOME only for this reader
            # test. No graphical application, session or user manager starts.
            child = subprocess.Popen(["/usr/bin/sleep", "20"], env=process_environment)
            try:
                manager = root / "systemctl"
                manager.write_text(
                    "#!/bin/bash\n"
                    "[[ $* == '--user show org.gnome.Shell@user.service -p MainPID --value' ]] || exit 90\n"
                    "printf '%s\\n' \"$FIXTURE_PID\"\nexit \"$FIXTURE_RC\"\n"
                )
                manager.chmod(0o700)
                script = root / "reader.sh"
                script.write_text(
                    "set -euo pipefail\nfail() { echo \"$*\" >&2; exit 1; }\n"
                    + BOUNDARY.replace("== /usr/bin/gnome-shell", "== " + expected_exe)
                )
                env = {"PATH": str(root) + ":/usr/bin:/bin", "LC_ALL": "C",
                       "FIXTURE_PID": str(child.pid) if pid is None else pid,
                       "FIXTURE_RC": str(manager_rc)}
                result = subprocess.run(["bash", str(script)], env=env,
                                        capture_output=True, text=True, timeout=5)
            finally:
                child.terminate()
                child.wait(timeout=5)
            self.assertEqual(result.stdout, "")
            return result.returncode

    def test_real_settings_pass_even_with_unrelated_multiline_data(self):
        self.assertEqual(self.run_boundary(EXPECTED | BAIT), 0)

    def test_multiline_data_cannot_supply_missing_settings(self):
        self.assertNotEqual(self.run_boundary(BAIT), 0)

    def test_multiline_data_cannot_override_wrong_settings(self):
        self.assertNotEqual(self.run_boundary(BAIT | {
            "GJS_DISABLE_JIT": "0", "JavaScriptCoreUseJIT": "1"}), 0)

    def test_each_missing_or_wrong_setting_is_rejected(self):
        for key in EXPECTED:
            with self.subTest(key=key):
                absent = {k: v for k, v in EXPECTED.items() if k != key}
                self.assertNotEqual(self.run_boundary(absent), 0)
                self.assertNotEqual(self.run_boundary(EXPECTED | {key: "unexpected"}), 0)

    def test_failed_manager_query_cannot_supply_a_valid_partial_pid(self):
        self.assertNotEqual(self.run_boundary(EXPECTED, manager_rc=1), 0)

    def test_invalid_manager_pid_is_rejected(self):
        self.assertNotEqual(self.run_boundary(EXPECTED, pid="0"), 0)

    def test_a_foreign_executable_cannot_count_as_gnome_shell(self):
        self.assertNotEqual(self.run_boundary(EXPECTED, expected_exe="/usr/bin/gnome-shell"), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
