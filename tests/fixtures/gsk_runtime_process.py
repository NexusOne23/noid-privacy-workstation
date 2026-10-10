#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the actual GNOME gate's process boundary with native read errors."""

import errno
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest


SOURCE = Path(sys.argv.pop(1)).read_text(encoding="utf-8")
START = "shell_pid=$(timeout"
END = "\nstate_dir=$RUNTIME_ROOT/noid-gsk-session-environment"
assert SOURCE.count(START) == SOURCE.count(END) == 1
BOUNDARY = START + SOURCE.split(START, 1)[1].split(END, 1)[0]
COMMAND = b"/usr/bin/gnome-shell\0--mode=user\0"


class RuntimeProcessTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix="noid-gsk-process-", dir="/var/tmp")
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.proc = self.root / "proc"
        self.process = self.proc / "424242"
        self.process.mkdir(parents=True)
        self.command = self.process / "cmdline"
        self.environment = self.process / "environ"
        self.command.write_bytes(COMMAND)
        self.environment.write_bytes(b"PATH=/usr/bin\0NOTE=private-fixture\0")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        manager = self.bin / "systemctl"
        manager.write_text("#!/bin/bash\n"
                           "[ \"$*\" = '--user show org.gnome.Shell@user.service "
                           "-p MainPID --value' ] || exit 90\n"
                           "printf '%s\\n' 424242\n")
        manager.chmod(0o700)
        # Only the process tree and the MainPID responder are private. Execute
        # the complete canonical boundary with native Bash/readers/Python.
        self.helper = self.root / "boundary.sh"
        self.helper.write_text("#!/bin/bash\nset -euo pipefail\n"
                               "fail() { echo \"$*\" >&2; exit 1; }\n" +
                               BOUNDARY.replace("/proc", str(self.proc)) + "\n")
        self.env = {"PATH": str(self.bin) + ":/usr/bin:/bin", "LC_ALL": "C.UTF-8"}

    def run_boundary(self):
        return subprocess.run(["bash", str(self.helper)], env=self.env,
                              capture_output=True, text=True, check=False, timeout=5)

    def assert_rejected(self):
        result = self.run_boundary()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_native_directory_read_error_control(self):
        self.environment.unlink()
        self.environment.mkdir()
        fd = os.open(self.environment, os.O_RDONLY)
        try:
            result = subprocess.run(["/usr/bin/tr", "\\0", "\\n"], stdin=fd,
                                    capture_output=True, check=False)
        finally:
            os.close(fd)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertTrue(result.stderr)

    def test_valid_process_without_renderer_passes(self):
        self.assertEqual(self.run_boundary().returncode, 0)

    def test_empty_environment_without_renderer_passes(self):
        self.environment.write_bytes(b"")
        self.assertEqual(self.run_boundary().returncode, 0)

    def test_actual_renderer_values_are_rejected(self):
        for value in (b"gl", b"vulkan", b""):
            with self.subTest(value=value):
                self.environment.write_bytes(b"GSK_RENDERER=" + value + b"\0")
                self.assert_rejected()

    def test_renderer_text_inside_another_value_is_not_a_variable(self):
        self.environment.write_bytes(b"NOTE=first line\nGSK_RENDERER=gl\0")
        self.assertEqual(self.run_boundary().returncode, 0)

    def test_native_environment_read_error_is_rejected(self):
        self.environment.unlink()
        self.environment.mkdir()
        self.assert_rejected()

    def test_disappearance_after_readability_preflight_is_rejected(self):
        self.command.unlink()
        os.mkfifo(self.command, 0o600)
        errors = []

        def feed_after_preflight():
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline:
                try:
                    fd = os.open(self.command, os.O_WRONLY | os.O_NONBLOCK)
                except OSError as exc:
                    if exc.errno != errno.ENXIO:
                        errors.append(exc)
                        return
                    time.sleep(0.01)
                    continue
                try:
                    self.environment.unlink()
                    os.write(fd, COMMAND)
                finally:
                    os.close(fd)
                return
            errors.append(AssertionError("gate never opened the command fixture"))

        writer = threading.Thread(target=feed_after_preflight, daemon=True)
        writer.start()
        result = self.run_boundary()
        writer.join(timeout=5)
        self.assertFalse(writer.is_alive())
        self.assertEqual(errors, [])
        self.assertNotEqual(result.returncode, 0)

    def test_truncated_command_record_is_rejected(self):
        self.command.write_bytes(COMMAND[:-1])
        self.assert_rejected()

    def test_truncated_environment_record_is_rejected(self):
        self.environment.write_bytes(b"NOTE=truncated")
        self.assert_rejected()

    def test_wrong_command_is_rejected(self):
        for command in (b"", b"/usr/bin/other\0--mode=user\0",
                        b"/usr/bin/gnome-shell\0--mode=gdm\0"):
            with self.subTest(command=command):
                self.command.write_bytes(command)
                self.assert_rejected()


if __name__ == "__main__":
    unittest.main(verbosity=2)
