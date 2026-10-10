#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Native rule serialization and actual Bash/Awk admission-function checks."""

from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest


SOURCE = Path(sys.argv[1]).read_text()
DESCRIPTOR_HASH = "A" * 43 + "="
PARENT_HASH = "B" * 43 + "="


class AdmissionAttributeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix="noid-usb-attributes-")
        cls.root = Path(cls.scratch.name)
        start = SOURCE.index("blocked_device_line() {\n")
        end = SOURCE.index("\n# Argument mode: allow by USBGuard runtime device ID.", start)
        functions = SOURCE[start:end]
        # Only map the data-file owner expectation to this disposable account;
        # field interpretation, file-type/mode/link checks and all tools stay real.
        ownership = '[ "$metadata" = 0:0:644:1 ]'
        if functions.count(ownership) != 1:
            raise AssertionError("admission data ownership fixture boundary changed")
        functions = functions.replace(
            ownership, f'[ "$metadata" = {os.getuid()}:{os.getgid()}:644:1 ]'
        )
        cls.functions = cls.root / "functions.sh"
        cls.functions.write_text(functions)
        cls.argument_mode = cls.root / "argument-mode.sh"
        cls.argument_mode.write_text(SOURCE[end:SOURCE.index("\nMODE_SWITCH_PRECURSOR=no", end)])
        (cls.root / "0bda:1a2b").write_text("StandardEject=1\n")
        (cls.root / "0bda:1a2b").chmod(0o644)

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def call(self, function, *arguments, stdin=None):
        return subprocess.run(
            [
                "bash", "-c",
                'set -euo pipefail; source "$1"; MODE_SWITCH_DATA_DIR=$2; '
                'MODE_SWITCH_RULE_LABEL=noid-modeswitch-portable-v1; '
                'shift 2; "$@"',
                "fixture", str(self.functions), str(self.root), function, *arguments,
            ],
            input=stdin,
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )

    def row(self, name="Plain device", interfaces="08:06:50", *,
            state="block", serial="", device_id="0bda:1a2b", runtime_id=9,
            label="", condition="", port="1-1", parent=PARENT_HASH, include_serial=True):
        serial_field = f' serial "{serial}"' if include_serial else ""
        specification = (
            f'{state} id {device_id}{serial_field} name "{name}" '
            f'hash "{DESCRIPTOR_HASH}" parent-hash "{parent}" via-port "{port}" '
            f'with-interface {interfaces} with-connect-type "hotplug"{label}{condition}'
        )
        result = subprocess.run(
            ["/usr/bin/usbguard-rule-parser", specification],
            capture_output=True, text=True, timeout=8, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        bodies = [
            line.removeprefix("OUTPUT: ") for line in result.stdout.splitlines()
            if line.startswith("OUTPUT: ")
        ]
        self.assertEqual(len(bodies), 1, result.stdout)
        return f"{runtime_id}: {bodies[0]}"

    def test_display_uses_real_interfaces(self):
        row = self.row("USB with-interface 08:06:50 label demo", "03:01:01")
        result = self.call("render_device_rows", "menu", stdin=row + "\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Interface: 03:01:01 | USBGuard ID: 9", result.stdout)
        self.assertNotIn(DESCRIPTOR_HASH, result.stdout)
        self.assertNotIn(PARENT_HASH, result.stdout)

    def test_display_preserves_escaped_name(self):
        result = self.call(
            "render_device_rows", "menu",
            stdin=self.row(r'USB \"quoted\" device') + "\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("device", result.stdout.splitlines()[0])

    def test_unknown_id_error_does_not_dump_private_descriptors(self):
        row = self.row("Visible device", serial="PRIVATE-SERIAL")
        result = subprocess.run(
            [
                "bash", "-c",
                'set -euo pipefail; source "$1"; BLOCKED=$2; argument_mode=$3; '
                'set -- 999; source "$argument_mode"',
                "fixture", str(self.functions), row, str(self.argument_mode),
            ],
            capture_output=True, text=True, timeout=8, check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Visible device", result.stderr)
        self.assertNotIn("PRIVATE-SERIAL", result.stderr)
        self.assertNotIn(DESCRIPTOR_HASH, result.stderr)
        self.assertNotIn(PARENT_HASH, result.stderr)

    def test_display_includes_all_interfaces(self):
        result = self.call(
            "render_device_rows", "menu",
            stdin=self.row(interfaces="{ 08:06:50 03:01:01 }") + "\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("03:01:01", result.stdout)
        self.assertIn("08:06:50", result.stdout)

    def test_precursor_class_ignores_quoted_data(self):
        for name, serial in (
            ("Plain keyboard", ""),
            ("USB with-interface 08:06:50 label demo", ""),
            ("Plain keyboard", "USB with-interface 08:06:50 label demo"),
        ):
            with self.subTest(name=name, serial=serial):
                result = self.call("is_modeswitch_precursor", self.row(name, "03:01:01", serial=serial))
                self.assertNotEqual(result.returncode, 0)

    def test_real_precursor_is_recognized(self):
        self.assertEqual(self.call("is_modeswitch_precursor", self.row()).returncode, 0)

    def test_generated_rule_with_quoted_keywords_is_retired(self):
        for name in ("Plain device", "USB if demo", "USB label demo"):
            with self.subTest(name=name):
                source = self.row(name)
                policy = self.row(name, state="allow", runtime_id=31)
                self.assertEqual(
                    self.call("is_generated_topology_allow_rule", source, policy).returncode, 0
                )

    def test_operator_label_and_condition_are_preserved(self):
        for suffix in ({"label": ' label "operator"'}, {"condition": " if true"}):
            with self.subTest(suffix=suffix):
                policy = self.row(state="allow", runtime_id=31, **suffix)
                self.assertNotEqual(
                    self.call("is_generated_topology_allow_rule", self.row(), policy).returncode, 0
                )

    def test_reduced_operator_rule_is_preserved(self):
        policy = self.row(state="allow", runtime_id=31, include_serial=False)
        self.assertNotEqual(
            self.call("is_generated_topology_allow_rule", self.row(), policy).returncode, 0
        )

    def test_runtime_state_change_keeps_identity(self):
        self.assertEqual(
            self.call("same_runtime_device", self.row(), self.row(state="allow")).returncode, 0
        )

    def test_quoted_whitespace_change_is_a_changed_identity(self):
        self.assertNotEqual(
            self.call("same_runtime_device", self.row("Two  spaces"), self.row("Two spaces")).returncode, 0
        )

    def test_malformed_rows_do_not_share_identity(self):
        for row in ("", '9: block name "unfinished', "9: block "):
            with self.subTest(row=row):
                self.assertNotEqual(self.call("same_runtime_device", row, row).returncode, 0)

    def test_correlation_requires_matching_port_and_parent(self):
        source = self.row()
        target = self.row("Next identity", "ff:ff:ff", device_id="1234:0001", runtime_id=22)
        self.assertEqual(self.call("modeswitch_target_line", source, target).stdout.strip(), target)
        wrong_port = self.row(device_id="1234:0001", runtime_id=22, port="1-2")
        wrong_parent = self.row(device_id="1234:0001", runtime_id=22, parent=DESCRIPTOR_HASH)
        for rows in (wrong_port, wrong_parent, target + "\n" + target):
            with self.subTest(rows=rows):
                self.assertNotEqual(self.call("modeswitch_target_line", source, rows).returncode, 0)

    def test_portable_rule_uses_real_descriptor_fields(self):
        row = self.row("USB with-interface 03:01:01 label demo")
        result = self.call("portable_modeswitch_rule", row)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.strip(),
            f'allow id 0bda:1a2b hash "{DESCRIPTOR_HASH}" with-interface 08:06:50 '
            'label "noid-modeswitch-portable-v1"',
        )

    def test_malformed_quoting_fails_visible(self):
        result = self.call("render_device_rows", "menu", stdin='9: block name "unfinished\n')
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
