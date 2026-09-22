#!/usr/bin/env python3
"""Exercise report creation and exact retention with native private files."""
# SPDX-License-Identifier: GPL-3.0-or-later

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest


if len(sys.argv) != 4 or os.getuid() == 0:
    raise SystemExit("usage: unprivileged python3 aide_reports.py MODULE_13 MODULE_42 MODULE_99")
M13, M42, M99 = (Path(p).read_text(encoding="utf-8") for p in sys.argv[1:])


def exactly_one(pattern, text):
    matches = re.findall(pattern, text, re.M | re.S)
    if len(matches) != 1:
        raise SystemExit(f"expected exactly one source block: {pattern}")
    return matches[0]


WRAPPER = exactly_one(r"<<'AIDE_CHECK_WRAPPER_EOF'\n(.*?)\nAIDE_CHECK_WRAPPER_EOF", M13)
ABORT = exactly_one(r"^(noid_aide_abort\(\) \{.*?^\})", WRAPPER)
WRITER = exactly_one(r"\nfi\n\n(?:#[^\n]*\n)*(AIDE_(?:REPORT_STAMP|CHECK_LOG)=.*?)\nchmod 0600 ", WRAPPER)
MISC = exactly_one(r"<<'MISC_LOGS_PRUNE_EOF'\n(.*?)\nMISC_LOGS_PRUNE_EOF", M42)
DELETE = exactly_one(r"^(delete_aged\(\) \{.*?^\})", MISC)
PRUNE = exactly_one(r"^(AIDE_REMOVED=0\n.*?)\n# Rotated libvirt", MISC)
CROSS_GATE = exactly_one(r"^# BEGIN M99_AIDE_REPORT_CONTRACT\n(.*?)^# END M99_AIDE_REPORT_CONTRACT", M99)
INVOCATION = "1" * 32  # Synthetic, never obtained from a host or a real unit.


class AideReports(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="noid-aide-reports.", dir="/var/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write(self, invocation, date_output="20260901-120500", date_exit=0, fail_mktemp=False):
        environment = {**os.environ, "LOG_DIR": str(self.root), "DATE_OUTPUT": date_output,
                       "DATE_EXIT": str(date_exit), "LC_ALL": "C"}
        environment.pop("INVOCATION_ID", None)
        if invocation is not None:
            environment["INVOCATION_ID"] = invocation
        script = "set -Eeuo pipefail\numask 077\n" + ABORT + "\ntrap noid_aide_abort ERR\n"
        script += 'date() { printf "%s\\n" "$DATE_OUTPUT"; return "$DATE_EXIT"; }\n'
        if fail_mktemp:
            script += "mktemp() { return 7; }\n"
        script += WRITER + '\nprintf "%s\\n" "$AIDE_CHECK_LOG"\n'
        return subprocess.run(["bash", "-c", script], env=environment, capture_output=True,
                              text=True, timeout=10)

    def test_scheduled_report_carries_exact_invocation_and_random_suffix(self):
        result = self.write(INVOCATION)
        self.assertEqual(result.returncode, 0, result.stderr)
        path = Path(result.stdout.strip())
        self.assertRegex(path.name, rf"^aide-check-20260901-120500\.{INVOCATION}\.[A-Za-z0-9]{{6}}\.log$")
        self.assertEqual(path.parent, self.root)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        repeated = self.write(INVOCATION)
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        self.assertNotEqual(repeated.stdout, result.stdout)
        self.assertTrue(path.is_file(), "another allocation must preserve the first report")

    def test_manual_reports_keep_legacy_names(self):
        for invocation in (None, ""):
            with self.subTest(invocation=invocation):
                result = self.write(invocation)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertRegex(Path(result.stdout.strip()).name,
                                 r"^aide-check-20260901-120500\.[A-Za-z0-9]{6}\.log$")

    def test_invalid_identity_never_creates_a_report(self):
        for identity in ("0" * 32, "A" * 32, "1" * 31, "../escape", INVOCATION + "\n"):
            with self.subTest(identity=identity):
                result = self.write(identity)
                self.assertEqual(result.returncode, 14, result.stderr)
                self.assertEqual(list(self.root.iterdir()), [])

    def test_failed_clock_read_cannot_be_hidden_by_successful_mktemp(self):
        result = self.write(INVOCATION, date_exit=7)
        self.assertEqual(result.returncode, 14, result.stderr)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_malformed_timestamp_cannot_escape_the_retention_contract(self):
        for output in ("", "wrong", "20260901-120500\nextra"):
            with self.subTest(output=output):
                result = self.write(INVOCATION, date_output=output)
                self.assertEqual(result.returncode, 14, result.stderr)
                self.assertEqual(list(self.root.iterdir()), [])

    def test_failed_report_allocation_stays_outside_drift_exit_codes(self):
        result = self.write(INVOCATION, fail_mktemp=True)
        self.assertEqual(result.returncode, 14, result.stderr)

    def test_retention_removes_only_old_exact_reports_and_archives(self):
        old = (
            f"aide-check-20260801-120000.{INVOCATION}.abc123.log",
            "aide-check-20260801-120000.abc123.log",
            "aide-baseline-review-20260801-120000.abc123.log",
            "aide.log.1", "aide.log-20260801.gz",
        )
        kept = (
            "aide.log", "unrelated.txt", "aide-check-backup.log",
            f"aide-check-20260801-120000.{INVOCATION}.abc123.log.keep",
            "aide-check-20260801-120000.short.abc123.log",
            f"aide-check-20260801-120000.{INVOCATION}.abc12.log",
            f"aide-baseline-review-20260801-120000.{INVOCATION}.abc123.log",
        )
        for name in (*old, *kept):
            path = self.root / name
            path.write_text("synthetic report marker\n", encoding="ascii")
            os.utime(path, (time.time() - 31 * 86400,) * 2)
        young = self.root / f"aide-check-20260901-120500.{INVOCATION}.def456.log"
        young.write_text("young report marker\n", encoding="ascii")
        linked = self.root / f"aide-check-20260801-120000.{INVOCATION}.ghi789.log"
        linked.symlink_to("unrelated.txt")
        script = "set -u\nCUTOFF_DAYS=30\nDELETE_FAILURES=0\nLOG_TAG=fixture\nlogger() { :; }\n"
        script += DELETE + "\n" + PRUNE.replace("/var/log/aide", '"$REPORT_DIR"')
        script += '\nprintf "%s\\n" "$AIDE_REMOVED"\n[ "$DELETE_FAILURES" -eq 0 ]\n'
        result = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                                env={**os.environ, "REPORT_DIR": str(self.root)}, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(len(old)))
        self.assertEqual({p.name for p in self.root.iterdir()}, {*kept, young.name, linked.name})
        repeated = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                                  env={**os.environ, "REPORT_DIR": str(self.root)}, timeout=10)
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        self.assertEqual(repeated.stdout.strip(), "0")
        self.assertEqual({p.name for p in self.root.iterdir()}, {*kept, young.name, linked.name})

    def test_cross_module_gate_rejects_either_side_of_a_format_mismatch(self):
        writer_path, prune_path = self.root / "writer.sh", self.root / "prune.sh"
        for label, writer, prune, expected in (
            ("matching", WRAPPER, MISC, 0),
            ("missing-writer-identity", WRAPPER.replace('AIDE_REPORT_PREFIX+=".$INVOCATION_ID"', ':'), MISC, 1),
            ("missing-retention-identity", WRAPPER, MISC.replace(r"([0-9a-f]{32}\.)?", ""), 1),
        ):
            with self.subTest(case=label):
                writer_path.write_text(writer, encoding="utf-8")
                prune_path.write_text(prune, encoding="utf-8")
                gate = CROSS_GATE.replace("/usr/local/sbin/noid-aide-check.sh", str(writer_path))
                gate = gate.replace("/usr/local/bin/noid-misc-logs-prune.sh", str(prune_path))
                result = subprocess.run(
                    ["bash", "-c", 'fail=0\nlog() { :; }\n' + gate + '\nexit "$fail"\n'],
                    capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(result.returncode, expected, result.stderr)


unittest.main(argv=[sys.argv[0]])
