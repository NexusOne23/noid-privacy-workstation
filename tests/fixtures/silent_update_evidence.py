#!/usr/bin/env python3
"""Exercise the release gate's actual readers without starting desktop services."""
import contextlib
import io
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(sys.argv.pop(1)).read_text()


def payload(marker):
    return SOURCE.split("<<'" + marker + "'", 1)[1].split("\n", 1)[1].split(
        "\n" + marker + "\n", 1
    )[0]


MUTABLE = payload("FWUPD_MUTABLE_EVIDENCE_PY")
ENVIRONMENT = payload("SOFTWARE_ENVIRONMENT_PY")
CLEANUP = SOURCE.split("cleanup() {", 1)[1].split("\nread_software_plugins()", 1)[0]


class MutableRemotes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="noid-silent-reader-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name) / "fwupd"
        self.base.mkdir(mode=0o700)
        self.remotes = self.base / "remotes.d"
        self.code = MUTABLE.replace('Path("/var/lib/fwupd")', f"Path({str(self.base)!r})")
        self.native_lstat = Path.lstat

    def run_reader(self, owner=0, unreadable=False):
        # Rootless structural runs use real temporary paths and file types;
        # only the root ownership contract is supplied through this transport.
        def metadata(path):
            result = self.native_lstat(path)
            values = list(result)
            values[stat.ST_UID] = owner
            values[stat.ST_GID] = 0
            return os.stat_result(values)

        with patch.object(Path, "lstat", metadata):
            if unreadable:
                with patch.object(Path, "iterdir", side_effect=PermissionError("fixture")):
                    exec(self.code, {})
            else:
                exec(self.code, {})

    def test_missing_optional_directory_and_empty_directory(self):
        self.run_reader()
        self.remotes.mkdir()
        self.run_reader()
        (self.remotes / "lvfs").mkdir()
        self.run_reader()

    def test_missing_required_state_directory(self):
        self.base.rmdir()
        with self.assertRaises(SystemExit):
            self.run_reader()

    def test_remote_file_directory_and_dangling_link(self):
        self.remotes.mkdir()
        target = self.remotes / "unexpected.conf"
        for kind in ("file", "directory", "symlink"):
            with self.subTest(kind=kind):
                if kind == "file":
                    target.write_text("[fwupd Remote]\nEnabled=true\n")
                elif kind == "directory":
                    target.mkdir()
                else:
                    target.symlink_to("missing")
                with self.assertRaises(SystemExit):
                    self.run_reader()
                if kind == "directory":
                    target.rmdir()
                else:
                    target.unlink()

    def test_redirected_remote_directory(self):
        self.remotes.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(SystemExit):
            self.run_reader()

    def test_wrong_owner_and_writable_mode(self):
        with self.assertRaises(SystemExit):
            self.run_reader(owner=12345)
        self.remotes.mkdir(mode=0o700)
        self.remotes.chmod(0o777)
        with self.assertRaises(SystemExit):
            self.run_reader()

    def test_enumeration_error_is_not_absence(self):
        self.remotes.mkdir()
        with self.assertRaises(PermissionError):
            self.run_reader(unreadable=True)


class SoftwareEnvironment(unittest.TestCase):
    def run_reader(self, data):
        out = io.StringIO()
        with patch.object(sys, "argv", ["reader", "123"]), contextlib.redirect_stdout(out):
            with patch.object(Path, "read_bytes", return_value=data):
                exec(ENVIRONMENT, {})
        return out.getvalue().strip()

    def test_record_boundaries(self):
        self.assertEqual(
            self.run_reader(b"NOTE=unrelated\nvalue\0GNOME_SOFTWARE_PLUGINS_ALLOWLIST=flatpak,dnf5\0"),
            "flatpak,dnf5",
        )
        for data in (
            b"NOTE=unrelated\nGNOME_SOFTWARE_PLUGINS_ALLOWLIST=flatpak\0",
            b"GNOME_SOFTWARE_PLUGINS_ALLOWLIST=flatpak\nextra\0",
            b"GNOME_SOFTWARE_PLUGINS_ALLOWLIST=flatpak\0GNOME_SOFTWARE_PLUGINS_ALLOWLIST=dnf5\0",
            b"GNOME_SOFTWARE_PLUGINS_ALLOWLIST=flatpak",
            b"",
        ):
            with self.subTest(data=data), self.assertRaises(SystemExit):
                self.run_reader(data)

    def test_native_process_positive_and_injected_negative(self):
        for environment, valid in (
            ({"GNOME_SOFTWARE_PLUGINS_ALLOWLIST": "flatpak,dnf5"}, True),
            ({"NOTE": "unrelated\nGNOME_SOFTWARE_PLUGINS_ALLOWLIST=flatpak,dnf5"}, False),
        ):
            child = subprocess.Popen(["/usr/bin/sleep", "20"], env=environment)
            try:
                result = subprocess.run(
                    [sys.executable, "-c", ENVIRONMENT, str(child.pid)],
                    capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(result.returncode == 0, valid)
                if valid:
                    self.assertEqual(result.stdout.strip(), "flatpak,dnf5")
            finally:
                child.terminate()
                child.wait(timeout=5)

    def test_unreadable_process_fails(self):
        with patch.object(sys, "argv", ["reader", "123"]):
            with patch.object(Path, "read_bytes", side_effect=PermissionError("fixture")):
                with self.assertRaises(PermissionError):
                    exec(ENVIRONMENT, {})


class Interruption(unittest.TestCase):
    def test_signals_cleanup_and_never_continue(self):
        for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=sig), tempfile.TemporaryDirectory() as td:
                work = Path(td) / "owned"
                work.mkdir()
                code = (
                    'set -euo pipefail\ntmp=$1\nsoftware_started=0\ncleanup() {'
                    + CLEANUP + f"\nkill -{sig.value} $$\nprintf CONTINUED\n"
                )
                result = subprocess.run(
                    ["bash", "-c", code, "fixture", str(work)],
                    capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(result.returncode, 128 + sig.value)
                self.assertNotIn("CONTINUED", result.stdout)
                self.assertFalse(work.exists())


if __name__ == "__main__":
    unittest.main()
