#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the actual BLS resolver without reading or writing live boot state."""

import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest


SOURCE = Path(sys.argv.pop(1)).read_text(encoding="utf-8")
RESOLVER = re.search(r"(?ms)^resolve_source_bls\(\) \{\n.*?^\}", SOURCE).group()
KERNEL = "7.1.8-test"


class BlsSourceTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(
            prefix="noid-bls-selection-", dir="/var/tmp")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.entries = self.root / "entries"
        self.entries.mkdir()
        # Native metadata checks apply to the fixture owner's UID/GID, with
        # the production file-type and mode restrictions preserved.
        resolver = RESOLVER.replace("/boot/loader/entries", str(self.entries))
        resolver = resolver.replace("%U:%G:%a", "%u:%g:%a")
        resolver = resolver.replace(
            "root:root:600|root:root:644",
            f"{os.getuid()}:{os.getgid()}:600|{os.getuid()}:{os.getgid()}:644")
        self.script = self.root / "resolver.sh"
        self.script.write_text(
            "#!/bin/bash\nset -euo pipefail\nlog() { :; }\n" + resolver
            + "\nresolve_source_bls " + shlex.quote(KERNEL) + " || exit 1\n"
            "printf '%s\\n' \"$SOURCE_BLS_ID\"\n", encoding="utf-8")

    def entry(self, name, version=KERNEL):
        path = self.entries / name
        path.write_text("title Fixture\nversion " + version + "\n", encoding="utf-8")
        path.chmod(0o600)
        return path

    def resolve(self):
        return subprocess.run(["bash", str(self.script)], capture_output=True,
                              text=True, timeout=5, check=False)

    def test_exact_version_selects_its_entry(self):
        self.entry("correct.conf")
        result = self.resolve()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "correct\n")

    def test_similar_version_is_not_the_running_kernel(self):
        self.entry("different.conf", "7a1b8-test")
        self.assertNotEqual(self.resolve().returncode, 0)

    def test_similar_version_does_not_hide_the_unique_exact_entry(self):
        self.entry("correct.conf")
        self.entry("different.conf", "7a1b8-test")
        result = self.resolve()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "correct\n")

    def test_duplicate_exact_versions_are_rejected(self):
        self.entry("first.conf")
        self.entry("second.conf")
        self.assertNotEqual(self.resolve().returncode, 0)

    def test_unreadable_entry_prevents_a_completeness_claim(self):
        self.entry("readable.conf")
        unreadable = self.entry("unreadable.conf")
        unreadable.chmod(0o000)
        self.addCleanup(unreadable.chmod, 0o600)
        # This positive control must really fail for the ordinary fixture user.
        with self.assertRaises(PermissionError):
            unreadable.read_text()
        self.assertNotEqual(self.resolve().returncode, 0)

    def test_absent_entries_are_rejected(self):
        self.assertNotEqual(self.resolve().returncode, 0)

    def test_selected_symlink_is_rejected(self):
        target = self.entry("target.txt")
        (self.entries / "link.conf").symlink_to(target)
        self.assertNotEqual(self.resolve().returncode, 0)

    def test_invalid_bls_identifier_is_rejected(self):
        self.entry("invalid name.conf")
        self.assertNotEqual(self.resolve().returncode, 0)


if __name__ == "__main__":
    unittest.main()
