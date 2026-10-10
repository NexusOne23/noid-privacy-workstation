#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Test the candidate nft boundary with isolated command transports."""

from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(sys.argv.pop(1)).read_text()
HELPER = re.search(r"nft_table_state\(\) \{\n.*?\n\}", SOURCE, re.S).group(0)
BOUNDARY = SOURCE.split("# NOID_NFT_BOUNDARY_BEGIN\n", 1)[1].split("# NOID_NFT_BOUNDARY_END", 1)[0]
TRANSPORT = r'''
nft() {
    case "$*" in
        '--json list tables')
            [[ $FIXTURE_MODE != inventory-error ]] || return 1
            [[ $FIXTURE_MODE != invalid-json ]] || { echo invalid; return 0; }
            if [[ -e $FIXTURE_ROOT/table ]]; then
                printf '{"nftables":[{"table":{"family":"inet","name":"%s"}}]}\n' "$PROBE_TABLE"
            else
                printf '{"nftables":[{"metainfo":{"json_schema_version":1}}]}\n'
            fi ;;
        'create table inet '*|'add table inet '*)
            [[ $FIXTURE_MODE != root-error ]] || return 1
            printf 'owned\n' > "$FIXTURE_ROOT/table" ;;
        'delete table inet '*)
            printf 'delete\n' >> "$FIXTURE_ROOT/actions"
            rm -f -- "$FIXTURE_ROOT/table" ;;
        *) return 90 ;;
    esac
}
setpriv() {
    case "$FIXTURE_MODE" in
        permitted) printf 'owned\n' > "$FIXTURE_ROOT/table"; return 0 ;;
        syntax-error) echo 'Error: syntax error' >&2; return 1 ;;
        launcher-error) echo 'setpriv: nft: No such file or directory' >&2; return 127 ;;
        empty-error) return 1 ;;
        cache-denial)
            printf 'netlink: Error: cache initialization failed: Operation not permitted\n' >&2 ;;
        *) printf 'Error: Could not process rule: Operation not permitted\nadd table inet %s\n^^^^\n' "$PROBE_TABLE" >&2 ;;
    esac
    return 1
}
'''


class NftBoundaryTests(unittest.TestCase):
    def run_boundary(self, mode="denied", existing=False):
        with tempfile.TemporaryDirectory(prefix="noid-nft-boundary-", dir="/var/tmp") as td:
            root = Path(td)
            if existing:
                (root / "table").write_text("pre-existing\n")
            code = ("set -euo pipefail\nfail() { echo \"$*\" >&2; exit 1; }\n"
                    "PROBE_TABLE=noid_unprivileged_boundary_probe\n"
                    + TRANSPORT + HELPER + "\n" + BOUNDARY)
            result = subprocess.run(["bash", "-c", code], capture_output=True, text=True,
                                    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C",
                                         "FIXTURE_ROOT": str(root), "FIXTURE_MODE": mode},
                                    timeout=5)
            table = (root / "table").read_text() if (root / "table").exists() else None
            actions = (root / "actions").read_text() if (root / "actions").exists() else ""
            return result.returncode, table, actions

    def test_native_rule_and_cache_permission_denials_pass(self):
        for mode in ["denied", "cache-denial"]:
            with self.subTest(mode=mode):
                rc, table, actions = self.run_boundary(mode)
                self.assertEqual((rc, table, actions), (0, None, "delete\n"))

    def test_preexisting_table_is_preserved_and_fails(self):
        rc, table, actions = self.run_boundary(existing=True)
        self.assertNotEqual(rc, 0)
        self.assertEqual((table, actions), ("pre-existing\n", ""))

    def test_failed_or_invalid_inventory_cannot_establish_absence(self):
        for mode in ["inventory-error", "invalid-json"]:
            with self.subTest(mode=mode):
                rc, _, actions = self.run_boundary(mode)
                self.assertNotEqual(rc, 0)
                self.assertEqual(actions, "")

    def test_failed_root_control_never_reaches_denial_pass(self):
        rc, _, actions = self.run_boundary("root-error")
        self.assertNotEqual(rc, 0)
        self.assertEqual(actions, "")

    def test_other_command_failures_are_not_permission_denials(self):
        for mode in ["syntax-error", "launcher-error", "empty-error"]:
            with self.subTest(mode=mode):
                self.assertNotEqual(self.run_boundary(mode)[0], 0)

    def test_unexpected_mutation_fails_and_is_cleaned_up(self):
        rc, table, actions = self.run_boundary("permitted")
        self.assertNotEqual(rc, 0)
        self.assertEqual((table, actions), (None, "delete\ndelete\n"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
