#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run the three real M25 record readers against private native helper processes.

Only the CLI function, notifier parsing block and GUI static method execute.
The update workflow, desktop, notifications and live boot state are untouched.
"""

import ast
import contextlib
import io
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest


SOURCE = Path(sys.argv.pop(1)).read_text(encoding="utf-8")
HELPER = "/usr/libexec/noid-reboot-readiness"
BLOCKED = ("none", "blocked", "state-unsafe")
SAFE_ROWS = (
    "schema=1", "activation=required", "safety=safe", "blockers=none",
    "running_kernel=7.1.8-test", "latest_kernel=7.1.8-test+prepared",
    "nvidia_running=unavailable", "nvidia_installed=unavailable",
)


def heredoc(marker):
    return SOURCE.split("<<'" + marker + "'\n", 1)[1].split("\n" + marker, 1)[0]


class RebootReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(
            prefix="noid-reboot-readers-", dir="/var/tmp")
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.root = Path(cls.scratch.name)
        cls.helper = cls.root / "helper"
        cls.record = cls.root / "record"
        cli = re.search(r"(?ms)^load_reboot_readiness\(\) \{\n.*?^\}",
                        heredoc("NOID_UPDATE_EOF")).group()
        notifier = heredoc("PENDING_REBOOT_EOF")
        notifier = notifier.split("# Read one exact record.", 1)[1]
        notifier = notifier[notifier.index("readiness=()\n"):]
        notifier = notifier.split("\n# Human-readable immediate status.", 1)[0]
        cls.cli = cls.root / "cli.sh"
        cls.notifier = cls.root / "notifier.sh"
        cls.cli.write_text(
            "#!/bin/bash\nset -uo pipefail\n" + cli.replace(
                HELPER, shlex.quote(str(cls.helper))) + "\n"
            "REBOOT_ACTIVATION=none REBOOT_SAFETY=blocked "
            "REBOOT_BLOCKER_SUMMARY=state-unsafe\n"
            "load_reboot_readiness || :\n"
            "printf '%s\\n' \"$REBOOT_ACTIVATION\" \"$REBOOT_SAFETY\" "
            "\"$REBOOT_BLOCKER_SUMMARY\"\n", encoding="utf-8")
        cls.notifier.write_text(
            "#!/bin/bash\nset -u\n" + notifier.replace(
                HELPER, shlex.quote(str(cls.helper))) + "\n"
            "printf '%s\\n' \"$activation\" \"$safety\" \"$blockers\"\n",
            encoding="utf-8")
        tree = ast.parse(heredoc("NOID_UPDATE_APP_EOF"))
        window = next(node for node in tree.body
                      if isinstance(node, ast.ClassDef)
                      and node.name == "UpdateWindow")
        method = next(node for node in window.body
                      if isinstance(node, ast.FunctionDef)
                      and node.name == "_reboot_readiness")
        probe = ast.ClassDef(name="Probe", bases=[], keywords=[],
                             body=[method], decorator_list=[])
        module = ast.fix_missing_locations(ast.Module(
            body=[probe], type_ignores=[]))

        def native_run(args, **kwargs):
            if args != [HELPER]:
                raise AssertionError("Unexpected helper invocation")
            return subprocess.run([str(cls.helper)], **kwargs)

        namespace = {"sys": sys, "re": re, "subprocess": SimpleNamespace(
            run=native_run, SubprocessError=subprocess.SubprocessError)}
        exec(compile(module, "<real-reboot-reader>", "exec"), namespace)
        cls.gui = namespace["Probe"]

    def check_record(self, rows=SAFE_ROWS, expected=BLOCKED, ending="exit 0",
                     suffix="\n", preserve_activation=False):
        self.record.write_text("\n".join(rows) + suffix, encoding="utf-8")
        self.helper.write_text(
            "#!/bin/bash\ncat -- " + shlex.quote(str(self.record))
            + " || exit 90\n" + ending + "\n", encoding="utf-8")
        self.helper.chmod(0o700)
        for reader in ("cli", "notifier", "gui"):
            with self.subTest(reader=reader, rows=tuple(rows), ending=ending,
                              suffix=suffix):
                if reader == "gui":
                    with contextlib.redirect_stderr(io.StringIO()):
                        actual = self.gui._reboot_readiness()
                else:
                    result = subprocess.run(
                        ["bash", str(getattr(self, reader))],
                        capture_output=True, text=True, timeout=5, check=True,
                        env={**os.environ, "LC_ALL": "C.UTF-8"})
                    actual = tuple(result.stdout.splitlines())
                if preserve_activation:
                    self.assertIn(actual[0], ("none", "required"))
                    self.assertEqual(actual[1:], expected[1:])
                else:
                    self.assertEqual(actual, expected)

    def test_valid_activation_states(self):
        for activation in ("none", "recommended", "required"):
            rows = list(SAFE_ROWS)
            rows[1] = "activation=" + activation
            self.check_record(rows, expected=(activation, "safe", "none"))

    def test_valid_blockers(self):
        for blockers in ("kernel-cmdline", "initramfs", "bls-identity",
                         "nvidia", "boot-inventory", "state-unsafe",
                         "nvidia-state", "initramfs,nvidia-state"):
            rows = list(SAFE_ROWS)
            rows[2:4] = ["safety=blocked", "blockers=" + blockers]
            self.check_record(rows, expected=("required", "blocked", blockers))

    def test_failed_helper_after_complete_record(self):
        for ending in ("exit 74", "cat -- " + shlex.quote(
                str(self.root / "missing-evidence")), 'kill -TERM "$$"',
                "exec 1>&-; sleep 0.03; exit 74"):
            self.check_record(ending=ending)

    def test_incomplete_and_extra_records(self):
        self.check_record(rows=())
        self.check_record(rows=SAFE_ROWS[:-1])
        self.check_record(rows=(*SAFE_ROWS, "extra=unavailable"))
        self.check_record(suffix="\n\n")

    def test_exact_field_names_and_order(self):
        for index in range(4, 8):
            rows = list(SAFE_ROWS)
            rows[index] = "unexpected=unavailable"
            self.check_record(rows)
        rows = list(SAFE_ROWS)
        rows[4], rows[5] = rows[5], rows[4]
        self.check_record(rows)
        rows[4] = rows[6]
        self.check_record(rows)

    def test_hardware_value_alphabet(self):
        for index in range(4, 8):
            for value in ("", "invalid value", "invalid/value", "kernel-é"):
                rows = list(SAFE_ROWS)
                rows[index] = rows[index].split("=", 1)[0] + "=" + value
                self.check_record(rows)

    def test_inconsistent_and_unknown_blockers(self):
        for safety, blockers in (("safe", "nvidia"), ("blocked", "none"),
                                 ("blocked", "none,nvidia"),
                                 ("blocked", "nvidia,none"),
                                 ("blocked", "nvidia,unknown"),
                                 ("blocked", "nvidia,")):
            rows = list(SAFE_ROWS)
            rows[2:4] = ["safety=" + safety, "blockers=" + blockers]
            # A notifier may retain a validated activation need while refusing
            # the inconsistent safety evidence; it must expose state-unsafe.
            self.check_record(rows, preserve_activation=True)


if __name__ == "__main__":
    unittest.main()
