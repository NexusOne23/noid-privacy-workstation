#!/usr/bin/env python3
"""Resolve shipped AIDE rules and compare synthetic symlink target vectors."""
# SPDX-License-Identifier: GPL-3.0-or-later

import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


if len(sys.argv) != 2 or os.getuid() == 0:
    raise SystemExit("usage: unprivileged python3 aide_rule_vectors.py MODULE_13")
MODULE = Path(sys.argv[1]).resolve(strict=True)
AIDE = shutil.which("aide")
if AIDE is None:
    raise SystemExit("native aide is required")
SECURE_LINES = re.findall(r"^SECURE = .+$", MODULE.read_text(encoding="utf-8"), re.M)
if len(SECURE_LINES) != 1:
    raise SystemExit("expected exactly one shipped SECURE definition")
SHIPPED = SECURE_LINES[0]
WITHDRAWN = "SECURE = p+u+g+s+n+b+acl+xattrs+sha256+sha512"

# Public AIDE database-format fields, verified against upstream v0.19.2
# include/attributes.h and src/attributes.c. These are synthetic input data,
# not a scan or an accepted baseline. No init/update/database_out is used.
NAME = 1 << 0
LINK = 1 << 1
PERM = 1 << 2
FTYPE = 1 << 35


class AideRuleVectors(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="noid-aide-vectors.", dir="/var/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = self.root / "rules.conf"
        self.before = self.root / "before.txt"
        self.after = self.root / "after.txt"

    def configure(self, secure):
        # Fedora's NORMAL definition; M13 also verifies the derivation against
        # the installed vendor configuration during compose. The vector paths
        # need not exist: path-check and compare never scan the filesystem.
        self.config.write_text(
            f"database_in=file:{self.before}\ndatabase_new=file:{self.after}\n"
            "database_attrs=E\nreport_url=stdout\n"
            f"NORMAL = R+sha512-m-c\n{secure}\n"
            "/noid-test-vector/n NORMAL\n/noid-test-vector/s SECURE\n",
            encoding="ascii",
        )

    def aide(self, operation):
        self.assertIn(operation.split("=", 1)[0], ("--path-check", "--compare"))
        return subprocess.run(
            [AIDE, f"--config={self.config}", operation],
            capture_output=True, text=True, timeout=15,
            env={**os.environ, "LC_ALL": "C"},
        )

    def attributes(self, group):
        result = self.aide(f"--path-check=l:/noid-test-vector/{group}/link")
        self.assertEqual(result.returncode, 0, result.stderr)
        matches = re.findall(
            rf"selective rule: '/noid-test-vector/{group} \(none\) ([a-z0-9_+]+)'",
            result.stdout,
        )
        self.assertEqual(len(matches), 1, result.stdout)
        return set(matches[0].split("+"))

    def vector(self, link, groups):
        lines = ["@@begin_db", "@@db_spec name lname perm attr"]
        for group, attrs in groups.items():
            # Project only the resolved l attribute into this fixture. All
            # other stored metadata is identical; the sole changed value is
            # the target. The separate superset test covers the full rule.
            mask = NAME | PERM | FTYPE | (LINK if "l" in attrs else 0)
            lines.append(f"/noid-test-vector/{group}/link ../{link}.unit 120777 {mask}")
        return "\n".join([*lines, "@@end_db", ""])

    def compare(self, secure, target, expected_changes):
        self.configure(secure)
        groups = {group: self.attributes(group) for group in ("n", "s")}
        self.before.write_text(self.vector("good", groups), encoding="ascii")
        self.after.write_text(self.vector(target, groups), encoding="ascii")
        result = self.aide("--compare")
        self.assertEqual(result.returncode, 4 if expected_changes else 0, result.stderr)
        if expected_changes:
            counts = re.findall(r"^\s*Changed entries:\s*(\d+)\s*$", result.stdout, re.M)
            self.assertEqual(counts, [str(expected_changes)], result.stdout)
        else:
            self.assertIn("AIDE found NO differences", result.stdout)

    def test_secure_is_a_superset_of_native_normal(self):
        self.configure(SHIPPED)
        normal, secure = self.attributes("n"), self.attributes("s")
        self.assertTrue(normal)
        self.assertIn("l", normal)
        self.assertFalse(normal - secure, f"SECURE drops {normal - secure}")
        self.assertTrue({"sha256", "b"} <= secure)

    def test_unchanged_targets_are_clean(self):
        self.compare(SHIPPED, "good", 0)

    def test_shipped_rules_detect_both_changed_targets(self):
        self.compare(SHIPPED, "evil", 2)

    def test_withdrawn_rule_misses_secure_target_change(self):
        self.compare(WITHDRAWN, "evil", 1)

    def test_malformed_input_is_not_a_successful_comparison(self):
        self.configure(SHIPPED)
        # AIDE permits leading comments/text and even empty input; use an
        # actually truncated record stream after its required opening marker.
        self.before.write_text("@@begin_db\n@@db_spec name lname perm attr\n", encoding="ascii")
        self.after.write_text("@@begin_db\n@@db_spec name lname perm attr\n", encoding="ascii")
        result = self.aide("--compare")
        self.assertGreaterEqual(result.returncode, 14, result.stderr)
        self.assertNotIn("AIDE found NO differences", result.stdout)


unittest.main(argv=[sys.argv[0]])
