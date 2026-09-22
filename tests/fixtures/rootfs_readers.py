#!/usr/bin/env python3
"""Run the complete rootfs verifier against native private directory failures."""
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


if len(sys.argv) != 2 or os.getuid() == 0:
    raise SystemExit("usage: unprivileged python3 rootfs_readers.py VERIFIER")
VERIFIER = Path(sys.argv[1]).resolve(strict=True)


class RootfsReaders(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="noid-rootfs-readers.", dir="/var/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "root"
        for relative in (
            "etc/NetworkManager/system-connections", "etc/nvme", "etc/ssh", "root",
            "var/lib/NetworkManager", "var/lib/chrony", "var/lib/dbus",
            "var/lib/systemd", "var/log/journal", "var/log/fixture",
        ):
            (self.root / relative).mkdir(parents=True, exist_ok=True)
        (self.root / "etc/machine-id").touch()
        (self.root / "etc/machine-id").chmod(0o444)
        (self.root / "var/lib/dbus/machine-id").symlink_to("/etc/machine-id")
        self.ssh = self.root / "etc/ssh"
        self.logs = self.root / "var/log/fixture"
        self.report_index = 0

    def verify(self, expected):
        self.report_index += 1
        report = self.base / f"report-{self.report_index}.json"
        result = subprocess.run(
            [sys.executable, "-B", "-I", str(VERIFIER), "--root", str(self.root),
             "--report", str(report), "--expected-uid", str(os.getuid()),
             "--expected-gid", str(os.getgid())],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, expected, result.stderr)
        if expected == 2:
            self.assertFalse(report.exists(), "incomplete inspection must not publish a clean report")
            self.assertNotIn("PASS", result.stdout)
        else:
            document = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(document["verdict"], "pass" if expected == 0 else "fail")
            self.assertEqual(bool(document["violations"]), expected != 0)

    def test_clean_directories_and_ordinary_ssh_configuration(self):
        (self.ssh / "sshd_config").write_text("# synthetic configuration\n", encoding="ascii")
        (self.ssh / "ssh_host_fixture_key.pub").write_text("synthetic public marker\n", encoding="ascii")
        self.verify(0)

    def test_absent_ssh_directory_remains_optional(self):
        self.ssh.rmdir()
        self.verify(0)

    def test_visible_compose_log(self):
        (self.logs / "compose.log").write_text("synthetic nonsecret log\n", encoding="ascii")
        self.verify(1)

    def test_visible_private_key_filename(self):
        (self.ssh / "ssh_host_fixture_key").write_text("synthetic nonkey marker\n", encoding="ascii")
        self.verify(1)

    def test_unreadable_log_directory(self):
        (self.logs / "compose.log").write_text("synthetic nonsecret log\n", encoding="ascii")
        self.addCleanup(self.logs.chmod, 0o700)
        self.logs.chmod(0)
        with self.assertRaises(PermissionError):
            list(self.logs.iterdir())
        self.verify(2)

    def test_unreadable_ssh_directory(self):
        (self.ssh / "ssh_host_fixture_key").write_text("synthetic nonkey marker\n", encoding="ascii")
        self.addCleanup(self.ssh.chmod, 0o700)
        self.ssh.chmod(0)
        with self.assertRaises(PermissionError):
            list(self.ssh.iterdir())
        self.verify(2)

    def test_regular_file_instead_of_ssh_directory(self):
        self.ssh.rmdir()
        self.ssh.write_text("synthetic wrong object\n", encoding="ascii")
        self.verify(2)

    def test_dangling_ssh_directory_link(self):
        self.ssh.rmdir()
        self.ssh.symlink_to("missing")
        self.verify(2)

    def test_ssh_directory_link(self):
        self.ssh.rmdir()
        outside = self.base / "outside"
        outside.mkdir()
        self.ssh.symlink_to(outside)
        self.verify(2)

    def test_log_directory_link_remains_forbidden(self):
        outside = self.base / "outside"
        outside.mkdir()
        (self.logs / "linked").symlink_to(outside)
        self.verify(1)

    def test_dangling_private_key_link_remains_forbidden(self):
        (self.ssh / "ssh_host_fixture_key").symlink_to("missing")
        self.verify(1)


unittest.main(argv=[sys.argv[0]])
