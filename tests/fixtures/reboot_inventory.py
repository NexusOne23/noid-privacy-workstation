#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the canonical reboot helper with native private find failures."""

import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest


SOURCE = Path(sys.argv.pop(1)).read_text(encoding="utf-8")
HELPER = SOURCE.split("<<'REBOOT_READINESS_EOF'\n", 1)[1].split(
    "\nREBOOT_READINESS_EOF", 1)[0]


class RebootInventoryTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(
            prefix="noid-reboot-inventory-", dir="/var/tmp")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.bin = self.root / "bin"
        self.modules = self.root / "modules"
        self.nvidia = self.root / "nvidia"
        self.queue = self.nvidia / "queue"
        self.bin.mkdir()
        (self.modules / "7.1.8-test").mkdir(parents=True)
        self.queue.mkdir(parents=True)
        self.nvidia.chmod(0o755)
        self.queue.chmod(0o755)
        self.script("uname", "printf '%s\\n' 7.1.8-test\n")
        self.script("modinfo", "exit 1\n")
        self.script("systemctl", "printf '%s\\n' inactive\nexit 3\n")
        # All injected failures still execute native find. Extra missing roots
        # yield an error plus partial data; queue removal occurs after the real
        # helper's metadata preflight and before find resolves the directory.
        self.script("find", r'''
case "$READINESS_FIXTURE_MODE:$1" in
    "kernel-partial:$READINESS_FIXTURE_MODULES"|"queue-partial:$READINESS_FIXTURE_QUEUE")
        exec /usr/bin/find "$READINESS_FIXTURE_ABSENT" "$@"
        ;;
    "queue-disappeared:$READINESS_FIXTURE_QUEUE")
        mv -- "$READINESS_FIXTURE_QUEUE" "$READINESS_FIXTURE_QUEUE.moved" || exit 90
        ;;
esac
exec /usr/bin/find "$@"
''')
        text = HELPER
        for before, after in (
                ("PATH=/usr/sbin:/usr/bin",
                 "PATH=" + shlex.quote(str(self.bin)) + ":/usr/sbin:/usr/bin"),
                ("firstboot_marker=/var/lib/noid-privacy/.firstboot-cmdline-reboot-required",
                 "firstboot_marker=" + shlex.quote(str(self.root / "firstboot"))),
                ("block_state=/run/noid-privacy/reboot-blocked",
                 "block_state=" + shlex.quote(str(self.root / "block-state"))),
                ("nvidia_state_dir=/var/lib/noid-nvidia-integrity",
                 "nvidia_state_dir=" + shlex.quote(str(self.nvidia))),
                ("find /lib/modules ", "find " + shlex.quote(str(self.modules)) + " "),
                ("nvidia_version_file=/proc/driver/nvidia/version",
                 "nvidia_version_file=" + shlex.quote(str(self.root / "nv-version"))),
                ("!= 0:0:755", f"!= {os.getuid()}:{os.getgid()}:755")):
            self.assertIn(before, text)
            text = text.replace(before, after)
        self.helper = self.root / "helper.sh"
        self.helper.write_text(text + "\n", encoding="utf-8")

    def script(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/bash\n" + body, encoding="utf-8")
        path.chmod(0o700)

    def run_helper(self, mode="normal"):
        result = subprocess.run(
            ["bash", str(self.helper)], capture_output=True, text=True,
            check=True, timeout=5, env={**os.environ,
                "READINESS_FIXTURE_MODE": mode,
                "READINESS_FIXTURE_MODULES": str(self.modules),
                "READINESS_FIXTURE_QUEUE": str(self.queue),
                "READINESS_FIXTURE_ABSENT": str(self.root / "absent")})
        rows = result.stdout.splitlines()
        self.assertEqual(len(rows), 8)
        self.assertEqual(rows[0], "schema=1")
        return dict(row.split("=", 1) for row in rows)

    def test_complete_empty_inventory_is_safe(self):
        result = self.run_helper()
        self.assertEqual(result["activation"], "none")
        self.assertEqual(result["safety"], "safe")
        self.assertEqual(result["blockers"], "none")

    def test_complete_kernel_delta_requires_activation(self):
        (self.modules / "7.1.9-test").mkdir()
        result = self.run_helper()
        self.assertEqual(result["activation"], "required")
        self.assertEqual(result["safety"], "safe")
        self.assertEqual(result["latest_kernel"], "7.1.9-test")

    def test_native_find_error_still_emits_partial_inventory(self):
        result = subprocess.run([
            "/usr/bin/find", str(self.root / "absent"), str(self.modules),
            "-mindepth", "1", "-maxdepth", "1", "-type", "d",
            "-printf", "%f\n"], capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "7.1.8-test\n")

    def test_partial_kernel_inventory_is_blocked(self):
        result = self.run_helper("kernel-partial")
        self.assertEqual(result["safety"], "blocked")
        self.assertEqual(result["blockers"], "boot-inventory")
        self.assertEqual(result["latest_kernel"], "unavailable")

    def test_complete_pending_queue_is_blocked(self):
        (self.queue / "fixture.pending").touch()
        result = self.run_helper()
        self.assertEqual(result["safety"], "blocked")
        self.assertEqual(result["blockers"], "nvidia")

    def test_native_find_error_still_emits_pending_evidence(self):
        pending = self.queue / "fixture.pending"
        pending.touch()
        result = subprocess.run([
            "/usr/bin/find", str(self.root / "absent"), str(self.queue),
            "-mindepth", "1", "-maxdepth", "1", "-type", "f",
            "-name", "*.pending", "-print", "-quit"],
            capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, str(pending) + "\n")

    def test_queue_disappearing_after_preflight_is_blocked(self):
        result = self.run_helper("queue-disappeared")
        self.assertFalse(self.queue.exists())
        self.assertTrue(self.queue.with_name("queue.moved").is_dir())
        self.assertEqual(result["safety"], "blocked")
        self.assertEqual(result["blockers"], "nvidia-state")

    def test_partial_pending_queue_is_blocked(self):
        (self.queue / "fixture.pending").touch()
        result = self.run_helper("queue-partial")
        self.assertEqual(result["safety"], "blocked")
        self.assertEqual(result["blockers"], "nvidia-state")


if __name__ == "__main__":
    unittest.main()
