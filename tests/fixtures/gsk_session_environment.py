#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run the full session helper against private manager-state fixtures."""

import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest


SOURCE = Path(sys.argv.pop(1)).read_text(encoding="utf-8")
HELPER = SOURCE.split("<<'GSK_SESSION_HELPER_EOF'\n", 1)[1].split(
    "\nGSK_SESSION_HELPER_EOF", 1)[0]


class SessionEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.assertNotEqual(os.geteuid(), 0, "run as an ordinary test user")
        scratch = tempfile.TemporaryDirectory(prefix="noid-gsk-env-", dir="/var/tmp")
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.runtime = self.root / "runtime"
        self.runtime.mkdir(mode=0o700)
        self.state = self.runtime / "noid-gsk-session-environment"
        self.state.mkdir(mode=0o700)
        self.marker = self.state / "applied"
        self.manager = self.root / "environment"
        self.calls = self.root / "calls"
        self.count = self.root / "count"
        self.manager.write_text("GSK_RENDERER=gl\n", encoding="utf-8")
        self.write_marker()
        self.script("systemctl", r'''
set -eu
printf '%s\n' "$*" >> "$GSK_FIXTURE_ROOT/calls"
case "$*" in
    '--user show-environment')
        count=0
        if [ -f "$GSK_FIXTURE_ROOT/count" ]; then
            count=$(cat "$GSK_FIXTURE_ROOT/count")
        fi
        count=$((count + 1))
        printf '%s\n' "$count" > "$GSK_FIXTURE_ROOT/count"
        if [ "$count" = "$GSK_FIXTURE_FAIL_READ" ]; then
            [ "$GSK_FIXTURE_PARTIAL" != yes ] || printf '%s\n' GSK_RENDERER=gl
            # This is a real systemctl failure against a nonexistent private
            # socket. Neither the system nor the active session bus is used.
            exec /usr/bin/systemctl --user show-environment
        fi
        exec /usr/bin/cat "$GSK_FIXTURE_ROOT/environment"
        ;;
    '--user unset-environment GSK_RENDERER')
        case "$GSK_FIXTURE_UNSET" in
            fail) exit 74 ;;
            retain) exit 0 ;;
        esac
        : > "$GSK_FIXTURE_ROOT/environment"
        ;;
    *) exit 90 ;;
esac
''')
        self.script("activation-updater", r'''
set -eu
[ "$*" = '--systemd GSK_RENDERER=gl' ] || exit 90
printf '%s\n' GSK_RENDERER=gl > "$GSK_FIXTURE_ROOT/next-environment"
sed '/^GSK_RENDERER=/d' "$GSK_FIXTURE_ROOT/environment" >> "$GSK_FIXTURE_ROOT/next-environment"
mv -- "$GSK_FIXTURE_ROOT/next-environment" "$GSK_FIXTURE_ROOT/environment"
''')
        text = HELPER
        for before, after in (
                ("PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                 "PATH=" + shlex.quote(str(self.bin)) + ":/usr/sbin:/usr/bin:/sbin:/bin"),
                ('"/run/user/$UID_NOW"', shlex.quote(str(self.runtime))),
                ("MATCHER=/usr/libexec/noid-gsk-hybrid-match", "MATCHER=/usr/bin/true"),
                ("MODE=/etc/xdg/noid-privacy/gsk-renderer.mode",
                 "MODE=" + shlex.quote(str(self.root / "mode"))),
                ("/usr/bin/dbus-update-activation-environment",
                 shlex.quote(str(self.bin / "activation-updater")))):
            self.assertIn(before, text)
            text = text.replace(before, after)
        self.helper = self.root / "helper.sh"
        self.helper.write_text(text + "\n", encoding="utf-8")
        self.env = {
            "PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8",
            "XDG_RUNTIME_DIR": str(self.runtime),
            "DBUS_SESSION_BUS_ADDRESS": "unix:path=" + str(self.root / "absent-bus"),
            "GSK_FIXTURE_ROOT": str(self.root), "GSK_FIXTURE_FAIL_READ": "0",
            "GSK_FIXTURE_PARTIAL": "no", "GSK_FIXTURE_UNSET": "normal"}

    def script(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/bash\n" + body, encoding="utf-8")
        path.chmod(0o700)

    def write_marker(self):
        self.marker.write_text("gl-session-apps\n", encoding="utf-8")
        self.marker.chmod(0o600)

    def run_helper(self, action="clear", **env):
        return subprocess.run(["bash", str(self.helper), action],
                              env={**self.env, **env}, capture_output=True,
                              text=True, check=False, timeout=5)

    def assert_no_unset(self):
        calls = self.calls.read_text() if self.calls.exists() else ""
        self.assertNotIn("unset-environment", calls)

    def test_native_private_bus_failure_control(self):
        result = subprocess.run(["/usr/bin/systemctl", "--user", "show-environment"],
                                env=self.env, capture_output=True, text=True,
                                check=False, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertTrue(result.stderr)

    def test_clear_gl_and_confirm_absence(self):
        self.assertEqual(self.run_helper().returncode, 0)
        self.assertEqual(self.manager.read_text(), "")
        self.assertFalse(self.marker.exists())
        self.assertEqual(self.count.read_text(), "2\n")

    def test_clear_preserves_known_administrator_values(self):
        for value in ("", "GSK_RENDERER=\n", "GSK_RENDERER=vulkan\n"):
            with self.subTest(value=value):
                self.write_marker()
                self.manager.write_text(value)
                self.assertEqual(self.run_helper().returncode, 0)
                self.assertEqual(self.manager.read_text(), value)
                self.assertFalse(self.marker.exists())
                self.assert_no_unset()

    def test_missing_marker_does_not_query_manager(self):
        self.marker.unlink()
        self.assertEqual(self.run_helper().returncode, 0)
        self.assertFalse(self.calls.exists())

    def test_unsafe_marker_is_retained_and_rejected(self):
        for kind in ("directory", "symlink", "dangling", "mode", "content"):
            with self.subTest(kind=kind):
                self.marker.unlink()
                if kind == "directory":
                    self.marker.mkdir()
                elif kind in ("symlink", "dangling"):
                    target = self.manager if kind == "symlink" else self.root / "absent"
                    self.marker.symlink_to(target)
                else:
                    self.write_marker()
                    if kind == "mode":
                        self.marker.chmod(0o644)
                    else:
                        self.marker.write_text("foreign\n")
                result = self.run_helper()
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(self.marker.exists() or self.marker.is_symlink())
                self.assertFalse(self.calls.exists())
                if self.marker.is_dir() and not self.marker.is_symlink():
                    self.marker.rmdir()
                    self.write_marker()

    def test_initial_read_failure_keeps_marker(self):
        self.assertNotEqual(self.run_helper(GSK_FIXTURE_FAIL_READ="1").returncode, 0)
        self.assertTrue(self.marker.exists())
        self.assert_no_unset()

    def test_partial_failed_initial_read_cannot_authorize_unset(self):
        result = self.run_helper(GSK_FIXTURE_FAIL_READ="1", GSK_FIXTURE_PARTIAL="yes")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.marker.exists())
        self.assert_no_unset()

    def test_post_unset_read_failure_keeps_marker(self):
        self.assertNotEqual(self.run_helper(GSK_FIXTURE_FAIL_READ="2").returncode, 0)
        self.assertTrue(self.marker.exists())

    def test_partial_failed_post_read_keeps_marker(self):
        result = self.run_helper(GSK_FIXTURE_FAIL_READ="2", GSK_FIXTURE_PARTIAL="yes")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.marker.exists())

    def test_failed_unset_keeps_marker(self):
        self.assertNotEqual(self.run_helper(GSK_FIXTURE_UNSET="fail").returncode, 0)
        self.assertTrue(self.marker.exists())

    def test_successful_unset_with_retained_value_is_rejected(self):
        self.assertNotEqual(self.run_helper(GSK_FIXTURE_UNSET="retain").returncode, 0)
        self.assertTrue(self.marker.exists())

    def test_large_complete_environment_is_cleared(self):
        self.manager.write_text("GSK_RENDERER=gl\n" + "PADDING=" + "x" * 300000 + "\n")
        self.assertEqual(self.run_helper().returncode, 0)
        self.assertEqual(self.manager.read_text(), "")
        self.assertFalse(self.marker.exists())

    def test_apply_publishes_confirmed_marker(self):
        self.marker.unlink()
        self.manager.write_text("")
        self.assertEqual(self.run_helper("apply").returncode, 0)
        self.assertEqual(self.marker.read_text(), "gl-session-apps\n")
        self.assertEqual(self.marker.stat().st_mode & 0o777, 0o600)

    def test_apply_read_failure_cannot_publish_marker(self):
        self.marker.unlink()
        result = self.run_helper("apply", GSK_FIXTURE_FAIL_READ="1",
                                 GSK_FIXTURE_PARTIAL="yes")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.marker.exists())

    def test_apply_with_large_complete_environment(self):
        self.marker.unlink()
        self.manager.write_text("PADDING=" + "x" * 300000 + "\n")
        self.assertEqual(self.run_helper("apply").returncode, 0)
        self.assertEqual(self.marker.read_text(), "gl-session-apps\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
