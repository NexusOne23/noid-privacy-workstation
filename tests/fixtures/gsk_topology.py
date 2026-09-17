#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check incomplete GPU evidence using native private sysfs-shaped trees."""

import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest


SOURCE = Path(sys.argv.pop(1)).read_text(encoding="utf-8")
MATCHER = SOURCE.split("<<'GSK_MATCH_EOF'\n", 1)[1].split("\nGSK_MATCH_EOF", 1)[0]


class TopologyTests(unittest.TestCase):
    def setUp(self):
        self.assertNotEqual(os.geteuid(), 0, "permission controls require an ordinary user")
        scratch = tempfile.TemporaryDirectory(prefix="noid-gsk-topology-", dir="/var/tmp")
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.sys = self.root / "sys"
        (self.sys / "class/drm").mkdir(parents=True)
        chassis = self.sys / "class/dmi/id/chassis_type"
        chassis.parent.mkdir(parents=True)
        chassis.write_text("10\n")
        self.igpu = self.gpu("igpu", "card0", "0x8086", "0x030000", "1")
        self.dgpu = self.gpu("dgpu", "card1", "0x10de", "0x030200", None)
        (self.igpu / "drm/card0/card0-eDP-1").mkdir()
        render = self.dgpu / "drm/renderD129"
        render.mkdir()
        (render / "device").symlink_to("../..")
        text = MATCHER
        for before, after in (
                ("SYS_ROOT=/sys", "SYS_ROOT=" + shlex.quote(str(self.sys))),
                ("CHASSIS_TYPE_FILE=/sys/class/dmi/id/chassis_type",
                 "CHASSIS_TYPE_FILE=" + shlex.quote(str(chassis)))):
            self.assertIn(before, text)
            text = text.replace(before, after)
        self.helper = self.root / "matcher.sh"
        self.helper.write_text(text + "\n")

    def gpu(self, name, card, vendor, gpu_class, boot_vga):
        device = self.sys / "devices" / name
        drm = device / "drm" / card
        drm.mkdir(parents=True)
        (drm / "device").symlink_to("../..")
        (self.sys / "class/drm" / card).symlink_to(drm)
        (device / "power").mkdir()
        for path, value in (("vendor", vendor), ("class", gpu_class),
                            ("power/control", "auto"), ("power/runtime_status", "active")):
            (device / path).write_text(value + "\n")
        if boot_vga is not None:
            (device / "boot_vga").write_text(boot_vga + "\n")
        return device

    def run_matcher(self, mutter=False):
        argv = ["bash", str(self.helper)]
        if mutter:
            argv += ["--mutter-headless-card", str(self.sys / "class/drm/card1")]
        return subprocess.run(argv, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"},
                              capture_output=True, text=True, check=False, timeout=5)

    def assert_rejected(self, mutter=False):
        result = self.run_matcher(mutter)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def deny_read(self, path, directory=False):
        original = path.stat().st_mode & 0o777
        self.addCleanup(path.chmod, original)
        path.chmod(0o111 if directory else 0o000)
        argv = (["/usr/bin/find", str(path), "-mindepth", "1", "-maxdepth", "1"]
                if directory else ["/usr/bin/cat", str(path)])
        result = subprocess.run(argv, capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0, "native permission control must fail")
        self.assertTrue(result.stderr)

    def test_supported_missing_3d_boot_attribute_matches(self):
        self.assertEqual(self.run_matcher().returncode, 0)
        result = self.run_matcher(True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "mutter-device-ignore\n")

    def test_explicit_non_primary_boot_attribute_matches(self):
        (self.dgpu / "boot_vga").write_text("0\n")
        self.assertEqual(self.run_matcher().returncode, 0)
        self.assertEqual(self.run_matcher(True).returncode, 0)

    def test_unreadable_offload_boot_attribute_is_not_absence(self):
        boot = self.dgpu / "boot_vga"
        boot.write_text("0\n")
        self.deny_read(boot)
        for mutter in (False, True):
            with self.subTest(mutter=mutter):
                self.assert_rejected(mutter)

    def test_invalid_offload_boot_values_are_not_non_primary(self):
        for value in ("", "2\n", "0\n1\n", "unknown\n"):
            (self.dgpu / "boot_vga").write_text(value)
            for mutter in (False, True):
                with self.subTest(value=value, mutter=mutter):
                    self.assert_rejected(mutter)

    def test_dangling_boot_attribute_is_not_absence(self):
        (self.dgpu / "boot_vga").symlink_to(self.root / "absent")
        for mutter in (False, True):
            with self.subTest(mutter=mutter):
                self.assert_rejected(mutter)

    def test_third_gpu_class_read_failure_cannot_hide_the_gpu(self):
        extra = self.gpu("extra", "card2", "0x1002", "0x030000", "0")
        self.assert_rejected()
        self.deny_read(extra / "class")
        self.assert_rejected()

    def test_unknown_additional_primary_cannot_authorize_mutter_ignore(self):
        extra = self.gpu("extra", "card2", "0x1002", "0x030000", "1")
        self.assert_rejected(True)
        self.deny_read(extra / "boot_vga")
        self.assert_rejected(True)

    def test_missing_additional_device_is_incomplete_inventory(self):
        extra = self.gpu("extra", "card2", "0x1002", "0x030000", "1")
        (extra / "drm/card2/device").unlink()
        for mutter in (False, True):
            with self.subTest(mutter=mutter):
                self.assert_rejected(mutter)

    def test_dangling_additional_card_is_incomplete_inventory(self):
        (self.sys / "class/drm/card2").symlink_to(self.root / "absent")
        for mutter in (False, True):
            with self.subTest(mutter=mutter):
                self.assert_rejected(mutter)

    def test_unreadable_connector_inventory_cannot_authorize_ignore(self):
        card = self.dgpu / "drm/card1"
        (card / "card1-DP-1").mkdir()
        self.assert_rejected(True)
        self.deny_read(card, directory=True)
        self.assert_rejected(True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
