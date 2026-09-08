#!/usr/bin/env python3
"""Exercise complete Lorax inventory/empty-target gates with native readers."""
# SPDX-License-Identifier: GPL-3.0-or-later

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


STAGERS = dict(zip(("overrides", "templates"), map(Path, sys.argv[1:])))
if len(sys.argv) != 3 or os.getuid() == 0:
    raise SystemExit("usage: unprivileged python3 lorax_inventory.py OVERRIDES TEMPLATES")


def extract(source, starts, end):
    matches = [start for start in starts if start in source]
    if len(matches) != 1 or source.count(matches[0]) != 1 or source.count(end) != 1:
        raise AssertionError("canonical Lorax gate is not unique")
    return source[source.index(matches[0]):source.index(end)]


class LoraxInventory(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="noid-lorax-inventory.", dir="/var/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.tree = self.base / "pylorax"
        self.tree.mkdir()
        self.sealed = self.tree / "sealed"
        self.sealed.mkdir()
        self.inventory = self.base / "rpm-files"
        self.inventory.write_text(f"{self.tree}\n{self.sealed}\n", encoding="utf-8")
        self.destination = self.base / "destination"
        self.destination.mkdir()
        self.addCleanup(self.destination.chmod, 0o700)
        self.addCleanup(self.sealed.chmod, 0o700)

    def run_inventory(self, name, injected=""):
        source = STAGERS[name].read_text(encoding="utf-8")
        end = "\nmonitor_source_sha256=" if name == "overrides" else "\nefi_sha256="
        block = extract(source, ("if ! diff -u \\\n", "if ! rpm_inventory="), end)
        prefix = (
            "set -euo pipefail\nexport LC_ALL=C.UTF-8\n"
            "SOURCE_ROOT=$1\nINVENTORY=$2\nNOID_RPM=(fixture_rpm)\n"
            'fixture_rpm() { /usr/bin/cat "$INVENTORY"; }\n'
        )
        root = self.base if name == "overrides" else self.tree
        return subprocess.run(
            ["bash", "-c", prefix + injected + block, "fixture", str(root), str(self.inventory)],
            capture_output=True, text=True, timeout=10,
        )

    def run_destination(self, name):
        source = STAGERS[name].read_text(encoding="utf-8")
        end = "\nfor input in" if name == "overrides" else '\n[ -f "$PATCH_FILE"'
        block = extract(source, ('[ -z "$(find "$DESTINATION"', "if ! destination_entry="), end)
        return subprocess.run(
            ["bash", "-c", "set -euo pipefail\nDESTINATION=$1\n" + block,
             "fixture", str(self.destination)],
            capture_output=True, text=True, timeout=10,
        )

    def test_matching_inventory(self):
        for name in STAGERS:
            with self.subTest(stager=name):
                self.assertEqual(self.run_inventory(name).returncode, 0)

    def test_unowned_file(self):
        (self.tree / "unowned.py").write_text("fixture\n", encoding="ascii")
        for name in STAGERS:
            with self.subTest(stager=name):
                self.assertEqual(self.run_inventory(name).returncode, 3)

    def test_missing_owned_file(self):
        with self.inventory.open("a", encoding="utf-8") as stream:
            stream.write(f"{self.tree}/missing.py\n")
        for name in STAGERS:
            with self.subTest(stager=name):
                self.assertEqual(self.run_inventory(name).returncode, 3)

    def test_native_unreadable_tree(self):
        self.sealed.chmod(0)
        control = subprocess.run(
            ["find", str(self.tree), "-xdev", "-print"], capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(control.returncode, 0)
        self.assertEqual(sorted(control.stdout.splitlines()), sorted(self.inventory.read_text().splitlines()))
        for name in STAGERS:
            with self.subTest(stager=name):
                self.assertEqual(self.run_inventory(name).returncode, 3)

    def test_producer_errors_after_complete_output(self):
        # The package listing is synthetic. Native cat/awk/sort still emit the
        # matching records; an injected status models an unsuccessful producer.
        for name in STAGERS:
            for stage, injected in (
                ("rpm", 'fixture_rpm() { /usr/bin/cat "$INVENTORY"; return 7; }\n'),
                ("awk", 'awk() { /usr/bin/awk "$@"; return 7; }\n'),
                ("sort", 'sort() { /usr/bin/sort "$@"; return 7; }\n'),
            ):
                with self.subTest(stager=name, producer=stage):
                    self.assertEqual(self.run_inventory(name, injected).returncode, 3)

    def test_empty_destination(self):
        for name in STAGERS:
            with self.subTest(stager=name):
                self.assertEqual(self.run_destination(name).returncode, 0)

    def test_nonempty_destination(self):
        (self.destination / "existing").write_text("retain fixture\n", encoding="ascii")
        for name in STAGERS:
            with self.subTest(stager=name):
                self.assertEqual(self.run_destination(name).returncode, 2)

    def test_native_unreadable_nonempty_destination(self):
        existing = self.destination / "existing"
        existing.write_text("retain fixture\n", encoding="ascii")
        self.destination.chmod(0o300)
        control = subprocess.run(
            ["find", str(self.destination), "-mindepth", "1", "-maxdepth", "1", "-print", "-quit"],
            capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(control.returncode, 0)
        self.assertEqual(control.stdout, "")
        for name in STAGERS:
            with self.subTest(stager=name):
                self.assertEqual(self.run_destination(name).returncode, 2)
        self.assertEqual(existing.read_text(encoding="ascii"), "retain fixture\n")


unittest.main(argv=[sys.argv[0]])
