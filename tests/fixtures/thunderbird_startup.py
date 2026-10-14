#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""First-launch selection, native-process distinction and opt-out boundaries.

The filesystem fixture substitutes vendor ownership and package queries only;
candidate VM browser gates independently exercise the real native worker.
"""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
source = Path(sys.argv.pop(1))
spec = importlib.util.spec_from_file_location("tb_startup", source)
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


class Startup(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root / "home"
        self.profile = self.home / ".thunderbird/default-release"
        self.profile.mkdir(parents=True, mode=0o700)
        self.registry = self.home / ".thunderbird/profiles.ini"
        self.registry.write_text("[Profile0]\nName=default-release\nIsRelative=1\nPath=default-release\n")
        self.archive = self.root / "vendor/dkim_verifier@pl.xpi"
        self.archive.parent.mkdir()
        self.archive.write_bytes(b"opaque reviewed fixture")
        self.metadata = self.root / "compat.json"
        self.metadata.write_text(json.dumps({"addons": {"dkim_verifier@pl": {
            "updates": [{"version": "6.3.0", "update_hash": "sha256:" +
                         hashlib.sha256(self.archive.read_bytes()).hexdigest()}]}}}))
        self.paths = {
            "/usr/lib64/thunderbird/distribution/extensions": self.archive.parent,
            "/usr/share/noid-thunderbird/dkim-compatibility.json": self.metadata,
            "/var/lib/noid-privacy/managed-extensions/dkim-compatibility.json": self.root / "absent.json",
        }
        self.query = SimpleNamespace(returncode=1, stdout="")
        self.executable = "/usr/bin/bash"

    def invoke(self, args=None):
        native_regular = worker.regular

        def regular(path):
            info = native_regular(path)
            if path in (self.archive, self.metadata):
                return SimpleNamespace(st_uid=0, st_mode=info.st_mode)
            return info

        def run(argv, **kwargs):
            if argv[0] == "/usr/bin/pgrep":
                return self.query
            if argv[0] == "/usr/bin/rpm":
                return SimpleNamespace(stdout="155.0")
            self.fail("unexpected subprocess")

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(worker, "Path", side_effect=lambda p:
                self.paths.get(str(p), Path(p))))
            stack.enter_context(patch.object(worker.pwd, "getpwuid", return_value=
                SimpleNamespace(pw_dir=str(self.home))))
            stack.enter_context(patch.dict(os.environ, {"HOME": str(self.home)}))
            stack.enter_context(patch.object(worker, "regular", side_effect=regular))
            stack.enter_context(patch.object(worker.subprocess, "run", side_effect=run))
            stack.enter_context(patch.object(worker.os, "readlink", return_value=self.executable))
            apply = stack.enter_context(patch.object(worker, "main"))
            worker.startup(["-P", "default-release"] if args is None else args)
            return apply

    def test_initial_profile_uses_native_distribution_install(self):
        apply = self.invoke()
        self.assertEqual(apply.call_count, 1)
        self.assertTrue(apply.call_args.kwargs["initialize"])
        self.assertEqual(apply.call_args.args[0][-1], str(self.profile))

    def test_missing_thunderbird_directory_uses_native_startup(self):
        self.registry.unlink()
        self.profile.rmdir()
        self.profile.parent.rmdir()
        self.assertEqual(self.invoke().call_count, 0)

    def test_missing_registry_uses_native_startup(self):
        self.registry.unlink()
        self.assertEqual(self.invoke().call_count, 0)

    def test_missing_profile_uses_native_startup(self):
        self.profile.rmdir()
        self.assertEqual(self.invoke().call_count, 0)

    def test_missing_home_is_not_treated_as_a_profile_reset(self):
        with patch.object(worker.pwd, "getpwuid", return_value=
                          SimpleNamespace(pw_dir=str(self.root / "absent-home"))), \
                patch.dict(os.environ, {"HOME": str(self.root / "absent-home")}):
            with self.assertRaises(FileNotFoundError):
                worker.startup(["-P", "default-release"])

    def test_dangling_profile_symlink_is_rejected(self):
        self.profile.rmdir()
        self.profile.symlink_to(self.root / "absent-profile", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "directory"):
            self.invoke()

    def test_dangling_registry_symlink_is_rejected(self):
        self.registry.unlink()
        self.registry.symlink_to(self.root / "absent-registry")
        with self.assertRaisesRegex(ValueError, "regular file"):
            self.invoke()

    def test_writable_profile_is_rejected(self):
        self.profile.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "directory"):
            self.invoke()

    def test_shell_launcher_does_not_suppress_preparation(self):
        self.query = SimpleNamespace(returncode=0, stdout="123\n")
        self.assertEqual(self.invoke().call_count, 1)

    def test_native_running_browser_keeps_remote_window_behavior(self):
        self.query = SimpleNamespace(returncode=0, stdout="123\n")
        self.executable = "/usr/lib64/thunderbird/thunderbird"
        self.assertEqual(self.invoke().call_count, 0)

    def test_failed_or_inconsistent_inventory_cannot_claim_absence(self):
        for rc, output in ((2, ""), (2, "123\n"), (1, "123\n"), (0, ""),
                           (0, "0\n"), (0, "invalid\n")):
            with self.subTest(rc=rc, output=output):
                self.query = SimpleNamespace(returncode=rc, stdout=output)
                with self.assertRaises(ValueError):
                    self.invoke()

    def test_profile_and_diagnostic_semantics_are_preserved(self):
        for args in (("--help",), ("--FULL-VERSION",), ("-P",), ("-p", "alternate"),
                     ("--PROFILE", "/var/tmp/alternate"), ("-P", "default-release", "-P", "other"),
                     ("-P", "default-release", "--profilemanager")):
            with self.subTest(args=args):
                self.assertEqual(self.invoke(args).call_count, 0)

    def test_removed_extension_is_not_reinstalled(self):
        (self.profile / "extensions.json").write_text('{"addons": []}')
        self.assertEqual(self.invoke().call_count, 0)

    def test_different_profile_payload_is_not_replaced(self):
        directory = self.profile / "extensions"
        directory.mkdir()
        target = directory / "dkim_verifier@pl.xpi"
        target.write_bytes(b"newer or user-owned payload")
        self.assertEqual(self.invoke().call_count, 0)
        self.assertEqual(target.read_bytes(), b"newer or user-owned payload")

    def test_metadata_digest_mismatch_blocks_initialization(self):
        self.archive.write_bytes(b"changed payload")
        with self.assertRaisesRegex(ValueError, "digest-bound"):
            self.invoke()

    def test_unsafe_registry_is_rejected(self):
        self.registry.chmod(0o666)
        with self.assertRaisesRegex(ValueError, "registry"):
            self.invoke()


if __name__ == "__main__":
    unittest.main()
