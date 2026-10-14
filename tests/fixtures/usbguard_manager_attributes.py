#!/usr/bin/python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the real manager with rules serialized by Fedora's native parser."""

import runpy
import subprocess
import sys
import unittest


MANAGER = runpy.run_path(sys.argv[1], run_name="noid_usbguard_attribute_fixture")
DESCRIPTOR_HASH = "A" * 43 + "="


class QuotedAttributeTests(unittest.TestCase):
    def rule(self, attributes):
        result = subprocess.run(
            ["/usr/bin/usbguard-rule-parser", "allow " + attributes],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        bodies = [
            line.removeprefix("OUTPUT: ")
            for line in result.stdout.splitlines()
            if line.startswith("OUTPUT: ")
        ]
        self.assertEqual(len(bodies), 1, result.stdout)
        rule = MANAGER["parse_rules"]("1: " + bodies[0])[0]
        rule.durable = True
        return rule

    def descriptor(self, name, interfaces, *, serial="", condition=""):
        serial_field = f' serial "{serial}"' if serial else ""
        return self.rule(
            f'id 1234:0001{serial_field} name "{name}" '
            f'hash "{DESCRIPTOR_HASH}" with-interface {interfaces}{condition}'
        )

    def test_hid_warning_uses_real_interfaces(self):
        for name in (
            "Plain keyboard",
            "USB with-interface 08:06:50 label demo",
            "USB with-interface 08:06:50 with-connect-type demo",
            r'USB \"with-interface 08:06:50 label demo\"',
        ):
            with self.subTest(name=name):
                rule = self.descriptor(name, "03:01:01")
                self.assertEqual(MANAGER["interfaces"](rule.body), "03:01:01")
                self.assertEqual(MANAGER["rule_kind"](rule), "HID/input — lockout risk")

    def test_controller_protection_uses_real_interfaces(self):
        for name in ("Plain hub", "USB with-interface 08:06:50 label demo"):
            with self.subTest(name=name):
                rule = self.descriptor(name, "09:00:00")
                self.assertEqual(MANAGER["rule_kind"](rule), "USB controller — protected")
                self.assertFalse(MANAGER["is_managed_revoke_candidate"](rule))

    def test_serial_cannot_override_interfaces(self):
        rule = self.descriptor(
            "Plain hub", "09:00:00", serial="USB with-interface 08:06:50 label demo"
        )
        self.assertEqual(MANAGER["rule_kind"](rule), "USB controller — protected")
        self.assertFalse(MANAGER["is_managed_revoke_candidate"](rule))

    def test_quoted_condition_is_only_device_text(self):
        rule = self.descriptor("USB if demo", "03:01:01")
        self.assertFalse(rule.conditional)
        self.assertEqual(MANAGER["rule_kind"](rule), "HID/input — lockout risk")
        self.assertTrue(MANAGER["is_managed_revoke_candidate"](rule))

    def test_actual_condition_remains_manual(self):
        rule = self.descriptor("Plain keyboard", "03:01:01", condition=" if true")
        self.assertTrue(rule.conditional)
        self.assertEqual(MANAGER["rule_kind"](rule), "conditional — manual review")
        self.assertFalse(MANAGER["is_managed_revoke_candidate"](rule))

    def test_quoted_id_does_not_make_a_broad_rule_guided(self):
        rule = self.rule(
            f'name "USB id 1234:0001 demo" hash "{DESCRIPTOR_HASH}" '
            "with-interface 08:06:50"
        )
        self.assertEqual(MANAGER["vidpid"](rule.body), "unknown")
        self.assertEqual(MANAGER["rule_kind"](rule), "broad/non-device rule — manual only")
        self.assertFalse(MANAGER["is_managed_revoke_candidate"](rule))

    def test_multifunction_device_retains_hid_warning(self):
        rule = self.descriptor(
            "USB with-interface 08:06:50 label demo", "{ 03:01:01 08:06:50 }"
        )
        self.assertEqual(MANAGER["rule_kind"](rule), "HID/input — lockout risk")

    def test_malformed_quoting_fails_closed(self):
        with self.assertRaises(MANAGER["ManagerError"]):
            MANAGER["interfaces"]('allow name "unfinished with-interface 08:06:50')


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
